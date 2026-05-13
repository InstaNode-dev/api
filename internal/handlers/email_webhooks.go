package handlers

// email_webhooks.go — inbound webhook endpoints for email-provider
// delivery feedback (bounces, unsubscribes, spam complaints).
//
// Endpoints:
//   POST /api/v1/email/webhook/brevo   — Brevo (Sendinblue) callbacks
//   POST /api/v1/email/webhook/ses     — Amazon SES via SNS notifications
//
// AUTH SHAPE — different per provider, intentionally not factored to a
// common interface because the three providers below verify auth in
// genuinely different ways:
//
//   Brevo:    HMAC-SHA256(key=BREVO_WEBHOOK_SECRET, msg=rawBody)
//             delivered hex-encoded in the X-Mailin-Custom header.
//   SES/SNS:  signed by AWS, but the cheap-and-shipping verification we
//             do today is the TopicArn match — the message includes
//             "TopicArn":"arn:...", and we reject anything that doesn't
//             match SES_SNS_SUBSCRIPTION_ARN. Full SNS signature
//             verification (download cert from SigningCertURL, RSA-verify)
//             is reserved for a follow-up; the ARN check stops drive-by
//             traffic but does not stop a determined attacker who has
//             the topic ARN.
//   SendGrid: ECDSA verify against a public key. Stub only today — the
//             handler is not wired into the router until the cutover.
//
// FAST RETURN — providers retry on slow responses (Brevo at 5s, SES at
// 30s), so we must:
//   1. Verify the signature in constant time.
//   2. Parse just enough of the payload to extract email + event_type.
//   3. INSERT (ON CONFLICT DO NOTHING — dedupe is at the model layer).
//   4. Return 200 immediately, even on partial failure (logged-and-swallow
//      for downstream errors). The only 4xx paths are bad signature /
//      bad payload.
//
// PII — the raw payload is stored in JSONB for audit, but the user-facing
// slog lines NEVER include it. Recipients' email addresses are logged at
// debug-level only; on production we expect log levels to suppress them.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
)

// EmailWebhookHandler holds the deps for both provider endpoints. db is
// the platform Postgres; cfg surfaces BrevoWebhookSecret + SESSNSTopicARN.
type EmailWebhookHandler struct {
	db  *sql.DB
	cfg *config.Config
}

// NewEmailWebhookHandler is the canonical constructor. Both endpoints are
// methods on this handler so the route registration stays compact.
func NewEmailWebhookHandler(db *sql.DB, cfg *config.Config) *EmailWebhookHandler {
	return &EmailWebhookHandler{db: db, cfg: cfg}
}

// ── Brevo ────────────────────────────────────────────────────────────────────

// brevoHeaderSignature is Brevo's signature header. They call this
// "X-Mailin-Custom" in the legacy docs but newer integrations emit
// "X-Sib-Signature"; we accept either. Both carry the same hex-encoded
// HMAC-SHA256 of the raw body keyed with the shared secret.
const (
	brevoHeaderSignatureLegacy = "X-Mailin-Custom"
	brevoHeaderSignatureNew    = "X-Sib-Signature"
)

// brevoEventPayload is the (single-event) shape Brevo POSTs. They also
// support batched arrays at a different URL — we only register the
// single-event endpoint today; a batched array would parse as a
// json.Decoder error and 400 out cleanly.
//
// Provider docs we're working from: https://developers.brevo.com/docs/transactional-webhooks
// FIELDS WE CARE ABOUT:
//   "event":      "hard_bounce" | "soft_bounce" | "unsubscribed" | "spam" | ...
//   "email":      recipient address
//   "reason":     free-text reason string (bounces)
//   "message-id": Brevo's delivery id; we hoist it under raw->>'message_id'
//                 for the dedupe index. The field name has a hyphen in
//                 Brevo's payload — we normalize it on insert below.
type brevoEventPayload struct {
	Event     string `json:"event"`
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	MessageID string `json:"message-id"`
}

// brevoEventTypeMap converts Brevo's event names to our normalized
// EmailEventType strings. Anything not in this map is dropped at the
// handler with a logged-and-200 path — Brevo sends a lot of event types
// (opened, clicked, delivered, etc.) that we don't need to suppress on.
var brevoEventTypeMap = map[string]string{
	"hard_bounce":  models.EmailEventTypeBounce,
	"soft_bounce":  models.EmailEventTypeSoftBounce,
	"unsubscribed": models.EmailEventTypeUnsubscribe,
	"spam":         models.EmailEventTypeSpamComplaint,
	"complaint":    models.EmailEventTypeSpamComplaint, // older Brevo shape
	"blocked":      models.EmailEventTypeBounce,         // blocked = permanent in practice
}

// Brevo handles POST /api/v1/email/webhook/brevo.
//
// Returns 401 on bad signature, 400 on unparseable body, 200 on every
// other case (including unknown event types — Brevo fires opens/clicks
// that we silently drop).
func (h *EmailWebhookHandler) Brevo(c *fiber.Ctx) error {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "email.webhook.brevo")
	defer span.End()

	body := c.Body()
	sig := c.Get(brevoHeaderSignatureNew)
	if sig == "" {
		sig = c.Get(brevoHeaderSignatureLegacy)
	}

	if !verifyBrevoSignature(body, sig, h.cfg.BrevoWebhookSecret) {
		slog.Warn("email.webhook.brevo.signature_failed",
			"have_secret", h.cfg.BrevoWebhookSecret != "",
			"have_signature", sig != "",
		)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_signature",
		})
	}

	var evt brevoEventPayload
	if err := json.Unmarshal(body, &evt); err != nil {
		slog.Warn("email.webhook.brevo.parse_failed", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_payload",
		})
	}

	normalized, ok := brevoEventTypeMap[strings.ToLower(evt.Event)]
	if !ok {
		// Brevo fires a lot of events we don't care about. 200 OK + skip.
		span.SetAttributes(attribute.String("brevo.event.unhandled", evt.Event))
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	if evt.Email == "" {
		slog.Warn("email.webhook.brevo.missing_email", "event", evt.Event)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	// Normalize message-id into raw->>'message_id' so the dedupe index
	// fires. Build a defensive copy of the body with the hyphenated key
	// rewritten to the underscore form — preserves the original payload
	// for audit AND gives the index the key it needs.
	raw := injectMessageID(body, evt.MessageID)

	if _, err := models.InsertEmailEvent(ctx, h.db, models.EmailEventProviderBrevo, normalized, evt.Email, evt.Reason, raw); err != nil {
		// Log + still 200. A DB blip should not cause Brevo to retry —
		// retries amplify the load on a struggling DB. We'll lose the
		// row, but the suppression query fails-open on the worker side
		// so no email is wrongly sent because of a missed insert.
		slog.Error("email.webhook.brevo.insert_failed",
			"event_type", normalized,
			"error", err,
		)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "persisted": false})
	}

	span.SetAttributes(
		attribute.String("email.event_type", normalized),
		attribute.String("email.provider", models.EmailEventProviderBrevo),
	)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
}

// verifyBrevoSignature checks hex(HMAC-SHA256(key=secret, msg=body)) == signature.
// Constant-time compare. Empty secret OR empty signature → false (closed).
func verifyBrevoSignature(body []byte, signature, secret string) bool {
	if secret == "" || signature == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(signature)) == 1
}

// ── SES via SNS ──────────────────────────────────────────────────────────────

// snsEnvelope is the SNS notification wrapper that fronts every SES bounce/
// complaint message. AWS posts JSON with these top-level fields:
//
//   Type:           "Notification" | "SubscriptionConfirmation"
//   TopicArn:       the topic that produced this notification
//   Message:        a string containing the SES bounce/complaint JSON
//   SubscribeURL:   only present on SubscriptionConfirmation
//
// We accept Notification only — operators handle the one-time subscription
// confirmation out-of-band via the AWS console. A SubscriptionConfirmation
// arriving here returns 200 with a hint logged at INFO so it's visible.
type snsEnvelope struct {
	Type         string `json:"Type"`
	TopicArn     string `json:"TopicArn"`
	Message      string `json:"Message"`
	SubscribeURL string `json:"SubscribeURL"`
}

// sesMessage is the SES bounce/complaint payload that arrives nested inside
// snsEnvelope.Message. SES has a notificationType discriminator + per-type
// sub-objects; we only pull what's needed to normalize.
type sesMessage struct {
	NotificationType string `json:"notificationType"` // "Bounce" | "Complaint" | "Delivery"
	Bounce           struct {
		BounceType        string `json:"bounceType"`     // "Permanent" | "Transient" | "Undetermined"
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			DiagnosticCode string `json:"diagnosticCode"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
	Complaint struct {
		ComplainedRecipients []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
	} `json:"complaint"`
	Mail struct {
		MessageID string `json:"messageId"`
	} `json:"mail"`
}

// SES handles POST /api/v1/email/webhook/ses.
//
// Auth is via SES_SNS_SUBSCRIPTION_ARN — the inbound envelope's TopicArn
// must match. Full SNS signature verification (RSA + cert download) is
// reserved for a follow-up; the ARN check rejects drive-by traffic but
// not a determined attacker who knows the ARN.
func (h *EmailWebhookHandler) SES(c *fiber.Ctx) error {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "email.webhook.ses")
	defer span.End()

	body := c.Body()
	var env snsEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		slog.Warn("email.webhook.ses.parse_envelope_failed", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_payload",
		})
	}

	if h.cfg.SESSNSTopicARN == "" || env.TopicArn == "" || subtle.ConstantTimeCompare([]byte(h.cfg.SESSNSTopicARN), []byte(env.TopicArn)) != 1 {
		slog.Warn("email.webhook.ses.topic_arn_mismatch",
			"have_configured_arn", h.cfg.SESSNSTopicARN != "",
			"have_envelope_arn", env.TopicArn != "",
		)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_signature",
		})
	}

	if env.Type == "SubscriptionConfirmation" {
		// Surface it at INFO so the operator sees the URL in logs and
		// can confirm the subscription out-of-band. We don't auto-confirm
		// — that would let an attacker who knows our ARN auto-subscribe
		// us to their topic.
		slog.Info("email.webhook.ses.subscription_confirmation_received",
			"subscribe_url_present", env.SubscribeURL != "",
		)
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "subscription_pending": true})
	}

	if env.Type != "Notification" {
		// Unknown envelope type — accept + skip so SNS doesn't retry.
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	var msg sesMessage
	if err := json.Unmarshal([]byte(env.Message), &msg); err != nil {
		slog.Warn("email.webhook.ses.parse_message_failed", "error", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":    false,
			"error": "invalid_message",
		})
	}

	// Map SES notificationType → our normalized event_type. Multiple
	// recipients may share one notification (SES batches per-mail); we
	// emit one email_events row per recipient.
	var recipients []struct {
		emailAddr string
		reason    string
	}
	var eventType string
	switch msg.NotificationType {
	case "Bounce":
		if msg.Bounce.BounceType == "Transient" {
			eventType = models.EmailEventTypeSoftBounce
		} else {
			eventType = models.EmailEventTypeBounce
		}
		for _, r := range msg.Bounce.BouncedRecipients {
			if r.EmailAddress == "" {
				continue
			}
			recipients = append(recipients, struct {
				emailAddr string
				reason    string
			}{r.EmailAddress, r.DiagnosticCode})
		}
	case "Complaint":
		eventType = models.EmailEventTypeSpamComplaint
		for _, r := range msg.Complaint.ComplainedRecipients {
			if r.EmailAddress == "" {
				continue
			}
			recipients = append(recipients, struct {
				emailAddr string
				reason    string
			}{r.EmailAddress, ""})
		}
	default:
		// Delivery, DeliveryDelay, etc. — not suppression-worthy.
		span.SetAttributes(attribute.String("ses.notification.unhandled", msg.NotificationType))
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	// Normalize message_id at the envelope level so all per-recipient
	// rows share one dedupe key + the SES messageId.
	innerRaw := injectMessageID([]byte(env.Message), msg.Mail.MessageID)

	for _, r := range recipients {
		if _, err := models.InsertEmailEvent(ctx, h.db, models.EmailEventProviderSES, eventType, r.emailAddr, r.reason, innerRaw); err != nil {
			slog.Error("email.webhook.ses.insert_failed",
				"event_type", eventType,
				"error", err,
			)
			// Continue with the next recipient — partial insert is
			// still net-positive vs all-or-nothing.
		}
	}

	span.SetAttributes(
		attribute.String("email.event_type", eventType),
		attribute.Int("email.recipient_count", len(recipients)),
	)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
}

// ── helpers ──────────────────────────────────────────────────────────────────

// injectMessageID rewrites the raw provider payload so it has a top-level
// "message_id" field with the provider's delivery id. The dedupe index
// reads raw->>'message_id'; without normalization, Brevo's "message-id"
// (hyphen) and SES's "messageId" (camelCase) wouldn't match the index.
//
// On parse failure or empty id, returns the original body unchanged —
// the partial UNIQUE index only fires when message_id is present, so
// missing-key rows still INSERT cleanly (just without dedupe).
func injectMessageID(body []byte, messageID string) json.RawMessage {
	if messageID == "" {
		return body
	}
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return body
	}
	m["message_id"] = messageID
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}
