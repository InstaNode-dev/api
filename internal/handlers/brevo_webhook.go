package handlers

// brevo_webhook.go — receiver-side machinery that closes the
// "201 ≠ delivered" gap for Brevo transactional email.
//
// WHY THIS EXISTS (2026-05-20 production incident):
//
// Brevo's transactional API returns 201 Created the moment it accepts a
// POST. The actual SMTP-relay delivery (or rejection) happens
// asynchronously inside Brevo's pipeline — sometimes seconds, sometimes
// minutes later, sometimes never. The worker's email forwarder stamps
// forwarder_sent.classification='success' on the 201 and advances the
// audit_log cursor, treating "API accepted" as "delivered".
//
// On 2026-05-20 we discovered every email since launch had been
// silently rejected at Brevo's relay because the sender domain wasn't
// validated. The worker logged success-after-success; zero users heard
// from us. The ledger lied because it confused API-acceptance with
// delivery.
//
// This file is the receiver side: a public endpoint Brevo POSTs to for
// every transactional event (delivered, soft_bounce, hard_bounce,
// blocked, complaint, error, deferred, unsubscribed). The handler:
//
//   1. Looks up the matching forwarder_sent row by provider_id (Brevo's
//      messageId, persisted by the worker at send time via the worker
//      change in the same PR).
//   2. Updates classification + delivered_at to reflect the ACTUAL
//      outcome instead of the API-acceptance state.
//
// AUTH SHAPE — URL TOKEN, NOT HMAC
//
// Brevo's transactional webhooks DON'T carry HMAC signatures by default.
// The two ways to lock the endpoint down are:
//
//   (a) Allowlist Brevo's source IP ranges. Fragile — Brevo's IPs change
//       without per-customer notice, and CIDR maintenance becomes an
//       ops burden disproportionate to the value.
//   (b) Put a shared secret in the URL path itself. Brevo configures the
//       webhook URL once in their dashboard; the path segment IS the
//       proof-of-knowledge.
//
// We pick (b): the route is `POST /webhooks/brevo/:secret`, verified
// against BREVO_WEBHOOK_SECRET via subtle.ConstantTimeCompare. A
// mismatch returns 401 + an opaque error envelope (no leaked secret in
// logs — only `have_secret` / `have_param` booleans).
//
// NOTE — DISTINCT FROM THE EXISTING /api/v1/email/webhook/brevo HMAC PATH:
// The HMAC-signed endpoint at /api/v1/email/webhook/brevo (see
// email_webhooks.go) handles BOUNCE-FOR-SUPPRESSION feedback (writes
// email_events rows the forwarder reads to skip future sends to
// bouncing inboxes). That endpoint requires Brevo's optional
// HMAC-signing header which is only emitted by newer integrations and
// requires the operator to enable signing per-callback in the dashboard.
//
// The new endpoint at /webhooks/brevo/:secret handles DELIVERY-LEDGER
// feedback (updates forwarder_sent.classification + delivered_at).
// Brevo can be configured to POST every event to BOTH endpoints — the
// suppression path stays HMAC-protected; the ledger path uses URL-token
// auth so it works even with HMAC disabled.
//
// IDEMPOTENCY
//
// Brevo retries on 5xx with exponential backoff. The handler MUST be
// idempotent: a re-delivery of the same event with the same messageId
// is expected. Our update is naturally idempotent because:
//   * UPDATE forwarder_sent SET classification = ... WHERE provider_id = $1
//     produces the same row state on every replay.
//   * delivered_at is set to GREATEST(delivered_at, $now) so a later
//     delivered event doesn't overwrite an earlier delivered_at with
//     a later one, and a bounce that arrives after a delivery is a
//     no-op on delivered_at (only classification flips).
//
// UNKNOWN MESSAGE ID
//
// A Brevo event whose messageId doesn't match any forwarder_sent row
// returns 200 OK (not 404). Returning 404 makes Brevo retry, which
// amplifies the orphan-event problem. The handler logs a WARN with the
// masked recipient + event_type so an operator can investigate, but
// the response is 200 so Brevo stops retrying. Common causes for
// orphans (all benign):
//
//   * Email sent before the worker started persisting the real
//     messageId (legacy rows with provider_id='audit-<uuid>').
//   * Email sent from a different cluster (staging callbacks arriving
//     at prod, or vice versa).
//   * Brevo-internal test sends (their dashboard "Send a test email"
//     button fires webhooks too).
//
// PII DISCIPLINE
//
// The raw payload is NEVER logged. Recipient addresses are masked via
// models.MaskEmail before they appear in any slog line. The messageId
// IS logged because it isn't PII — it's Brevo's internal opaque
// identifier.

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"instant.dev/internal/config"
	"instant.dev/internal/metrics"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// ── Named constants per CLAUDE.md feedback_no_hardcoded_strings ────────────

const (
	// brevoWebhookRoutePath is the public path Brevo POSTs to. Stored
	// as a named constant so router.go and the OpenAPI generator
	// can't drift from each other. The :secret segment is the
	// proof-of-knowledge — verified against config.BrevoWebhookSecret.
	brevoWebhookRoutePath = "/webhooks/brevo/:secret"

	// brevoSecretURLParam is the Fiber URL param name. Matches the
	// :secret segment above.
	brevoSecretURLParam = "secret"

	// brevoProviderName is the provider label used everywhere
	// forwarder_sent.provider is filtered. Matches the worker's
	// providerNameBrevo constant — kept duplicated here rather than
	// imported so the api binary doesn't pull the worker package.
	brevoProviderName = "brevo"

	// brevoMaxBodyBytes caps the payload we'll read from Brevo. A
	// transactional-event envelope is ~1 KB at most; 16 KiB is a
	// generous ceiling that bounds an abusive payload without
	// rejecting a malformed-but-legitimate one.
	brevoMaxBodyBytes = 16 * 1024
)

// ── classification values we WRITE (extends the worker's existing set) ────

const (
	// LedgerClassDelivered marks a forwarder_sent row whose Brevo
	// 'delivered' event arrived — the SMTP relay confirmed delivery
	// to the recipient MX. This is the only event that also stamps
	// delivered_at.
	LedgerClassDelivered = "delivered"

	// LedgerClassBouncedHard marks a permanent address failure. Brevo
	// 'hard_bounce' event. The recipient is unreachable forever.
	LedgerClassBouncedHard = "bounced_hard"

	// LedgerClassBouncedSoft marks a transient delivery problem. Brevo
	// 'soft_bounce' event. The recipient may be reachable later.
	LedgerClassBouncedSoft = "bounced_soft"

	// LedgerClassRejected marks a relay-side rejection. Brevo 'blocked'
	// event — sender / domain blocked at the relay (our sender domain
	// not validated, our IP on a blocklist, etc.).
	LedgerClassRejected = "rejected"

	// LedgerClassComplaint marks a recipient marking the message as
	// spam. Brevo 'complaint' / 'spam' event.
	LedgerClassComplaint = "complaint"

	// LedgerClassDeferred marks Brevo holding the message. 'deferred'
	// event — recipient MX returned a temporary failure, Brevo will
	// retry.
	LedgerClassDeferred = "deferred"

	// LedgerClassUnsubscribed marks the recipient pressing
	// unsubscribe. Brevo 'unsubscribed' event.
	LedgerClassUnsubscribed = "unsubscribed"

	// LedgerClassError marks a non-classified failure. Brevo 'error'
	// event — generic SMTP error not categorised by Brevo into
	// hard/soft/blocked.
	LedgerClassError = "error"
)

// brevoEventHandler is the per-event handler signature. Each event Brevo
// publishes maps to ONE handler — the coverage test
// (TestBrevoWebhook_EveryDocumentedEventHasHandler) iterates this
// registry and asserts every Brevo-documented event has a branch.
//
// Per CLAUDE.md rule 18 (registry-iterating regression tests, not hand-
// typed lists), additions are caught at CI time: a new Brevo event
// added to brevoDocumentedEvents but not to brevoEventHandlers fails
// the registry test.
type brevoEventHandler func(ctx context.Context, h *BrevoTransactionalWebhookHandler, evt brevoTransactionalEvent) (matched bool, err error)

// brevoEventHandlers is the dispatch map. Adding a new Brevo event =
// one line here + one line in brevoDocumentedEvents.
var brevoEventHandlers = map[string]brevoEventHandler{
	brevoEventDelivered:    handleBrevoDelivered,
	brevoEventSoftBounce:   makeClassUpdater(LedgerClassBouncedSoft),
	brevoEventHardBounce:   makeClassUpdater(LedgerClassBouncedHard),
	brevoEventBlocked:      makeClassUpdater(LedgerClassRejected),
	brevoEventComplaint:    makeClassUpdater(LedgerClassComplaint),
	brevoEventDeferred:     makeClassUpdater(LedgerClassDeferred),
	brevoEventUnsubscribed: makeClassUpdater(LedgerClassUnsubscribed),
	brevoEventError:        makeClassUpdater(LedgerClassError),
}

// brevoDocumentedEvents is the canonical list of every event the Brevo
// transactional webhook will deliver per the published docs:
// https://developers.brevo.com/docs/transactional-webhooks. The
// coverage test asserts every entry has a handler.
//
// "spam" is included as an alias for "complaint" — older Brevo
// integrations emit "spam"; newer ones emit "complaint". Both flow to
// LedgerClassComplaint.
var brevoDocumentedEvents = []string{
	brevoEventDelivered,
	brevoEventSoftBounce,
	brevoEventHardBounce,
	brevoEventBlocked,
	brevoEventComplaint,
	brevoEventDeferred,
	brevoEventUnsubscribed,
	brevoEventError,
}

// Event-name constants. Brevo uses lowercase, underscore-separated
// strings in the "event" field. Naming kept verbatim with their docs.
const (
	brevoEventDelivered    = "delivered"
	brevoEventSoftBounce   = "soft_bounce"
	brevoEventHardBounce   = "hard_bounce"
	brevoEventBlocked      = "blocked"
	brevoEventComplaint    = "complaint"
	brevoEventDeferred     = "deferred"
	brevoEventUnsubscribed = "unsubscribed"
	brevoEventError        = "error"
	// brevoEventSpam is an alias for "complaint" emitted by older
	// integrations. Mapped to the same handler in the
	// brevoNormalizeEvent function below.
	brevoEventSpam = "spam"
)

// brevoTransactionalEvent is the subset of Brevo's webhook payload we
// care about. Brevo includes many more fields (tags, link, ts_epoch,
// ts_event, sending_ip, message_id_v3, etc.) that we deliberately drop
// — the ledger update only needs the messageId, event type, and
// recipient (for the warn log on unknown messageIds).
//
// The "message-id" key has a hyphen in Brevo's payload — Go's json
// tag handles the renaming. We store the parsed value in MessageID
// (camelCase) internally.
//
// Date is parsed only opportunistically. Brevo's docs say it's
// formatted "%Y-%m-%d %H:%M:%S" with a timezone offset, but in
// practice we've observed three formats; rather than negotiate them,
// we stamp delivered_at = now() server-side which is good-enough for
// "did this event arrive in our pipeline" and is monotonic without
// trusting the upstream clock.
type brevoTransactionalEvent struct {
	Event     string `json:"event"`
	Email     string `json:"email"`
	MessageID string `json:"message-id"`
	Subject   string `json:"subject"`
	Reason    string `json:"reason"`
	Date      string `json:"date"`
}

// BrevoTransactionalWebhookHandler holds the deps for the
// /webhooks/brevo/:secret endpoint. db is the platform Postgres
// (forwarder_sent lives here); cfg surfaces BrevoWebhookSecret for the
// URL-token compare.
type BrevoTransactionalWebhookHandler struct {
	db  *sql.DB
	cfg *config.Config
}

// NewBrevoTransactionalWebhookHandler is the canonical constructor.
func NewBrevoTransactionalWebhookHandler(db *sql.DB, cfg *config.Config) *BrevoTransactionalWebhookHandler {
	return &BrevoTransactionalWebhookHandler{db: db, cfg: cfg}
}

// brevoNormalizeEvent maps the inbound event string to its canonical
// dispatch key. Handles the "spam" → "complaint" aliasing plus
// lowercasing. Returned key is guaranteed to be either an entry in
// brevoEventHandlers or "" (unknown event).
func brevoNormalizeEvent(in string) string {
	e := strings.ToLower(strings.TrimSpace(in))
	if e == brevoEventSpam {
		return brevoEventComplaint
	}
	return e
}

// Receive handles POST /webhooks/brevo/:secret.
//
// Returns:
//   200 OK on every accepted event (delivered, bounce, complaint, ...).
//   200 OK on unknown messageId (logged WARN — Brevo retries on 5xx,
//          we never want to amplify orphan traffic).
//   200 OK on unhandled event types (logged INFO — Brevo emits events
//          we don't track, e.g. 'request', 'click', 'open' — they all
//          come through this endpoint by default).
//   400   on malformed JSON.
//   401   on URL secret mismatch.
//   500   reserved for true DB outages (Brevo retries, which is the
//         right behaviour — the event is real, we just can't persist
//         it right now).
func (h *BrevoTransactionalWebhookHandler) Receive(c *fiber.Ctx) error {
	ctx, span := otel.Tracer("instant.dev/handlers").Start(c.UserContext(), "webhook.brevo.transactional")
	defer span.End()

	// URL-token auth. The secret is the :secret path segment, compared
	// in constant time against config.BrevoWebhookSecret. Empty
	// configured secret = closed (cannot be matched by any inbound
	// value). Empty inbound secret is rejected before the compare so
	// we can't be tricked by a configured-empty / inbound-empty case
	// matching.
	gotSecret := c.Params(brevoSecretURLParam)
	if gotSecret == "" || h.cfg.BrevoWebhookSecret == "" ||
		subtle.ConstantTimeCompare([]byte(gotSecret), []byte(h.cfg.BrevoWebhookSecret)) != 1 {
		// PII-safe log: NEVER log the secret value itself, only
		// presence booleans. An operator debugging a 401 storm sees
		// "have_configured_secret:true have_url_param:false" and
		// knows the Brevo dashboard config is missing the secret.
		haveConfigured := h.cfg.BrevoWebhookSecret != ""
		haveParam := gotSecret != ""
		slog.Warn("webhook.brevo.secret_mismatch",
			"have_configured_secret", haveConfigured,
			"have_url_param", haveParam,
		)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("unauthorized").Inc()
		// B18 wave-3 hardening (2026-05-21): emit an audit_log row on
		// every unauthorized attempt so an operator dashboard can chart
		// "N auth failures / hour" without grepping NR logs. Best-effort
		// via safego.Go — a DB outage MUST NOT block the 401 response we
		// owe the caller. Metadata carries presence booleans + the masked
		// source-IP subnet ONLY: never the secret value, never the raw
		// source IP.
		if h.db != nil {
			subnet := maskSourceIP(c.IP())
			safego.Go("brevo.webhook.unauthorized.audit", func() {
				meta, _ := json.Marshal(map[string]any{
					"have_configured_secret": haveConfigured,
					"have_url_param":         haveParam,
					"source_ip_subnet":       subnet,
				})
				_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
					Actor:    "system",
					Kind:     models.AuditKindBrevoWebhookUnauthorized,
					Summary:  "Brevo webhook URL-token compare failed",
					Metadata: meta,
				})
			})
		}
		// B13-F7 / B18 wave-3: hydrate the canonical ErrorResponse envelope
		// (ok/error/message/request_id/retry_after_seconds/agent_action) so
		// schema validators on the wire see the same 4xx shape every other
		// handler emits.
		//
		// API-6 (QA 2026-05-29): use the Brevo-specific error code
		// `brevo_secret_mismatch` instead of the generic `unauthorized` so
		// the canonical agent_action correctly tells the OPERATOR to fix
		// their Brevo dashboard config, instead of telling a USER to log
		// in for a new INSTANODE_TOKEN (this webhook is unrelated to user
		// auth). HTTP status stays 401 — only the error CODE + agent_action
		// copy change, so existing operator alerting that pivots off
		// `metrics.BrevoWebhookEventsTotal{result="unauthorized"}` is
		// unaffected.
		return respondError(c, fiber.StatusUnauthorized, "brevo_secret_mismatch",
			"Brevo webhook URL secret did not match the configured value.")
	}

	body := c.Body()
	if len(body) > brevoMaxBodyBytes {
		// Truncate the parse path — a payload > 16 KiB cannot be a
		// legitimate Brevo event envelope. We still 200 the response
		// so Brevo doesn't retry indefinitely; we log loud so the
		// operator sees the anomaly.
		slog.Warn("webhook.brevo.payload_too_large",
			"size_bytes", len(body),
			"cap_bytes", brevoMaxBodyBytes,
		)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("oversized").Inc()
		// B13-F7: canonical 4xx envelope on every webhook reject so a
		// schema validator on the wire sees the documented shape.
		return respondError(c, fiber.StatusBadRequest, "payload_too_large",
			"Brevo webhook payload exceeded the 16 KiB cap.")
	}

	var evt brevoTransactionalEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		// Brevo sometimes sends a JSON array of events (legacy batched
		// shape). We register the single-event URL only — a batched
		// inbound parses as a json.Unmarshal error and 400s. An
		// operator who sees a 400 storm should re-check the Brevo
		// dashboard's "Single event per webhook call" toggle.
		slog.Warn("webhook.brevo.parse_failed", "error", err)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("invalid_payload").Inc()
		// B13-F7: canonical 4xx envelope on every webhook reject.
		return respondError(c, fiber.StatusBadRequest, "invalid_payload",
			"Brevo webhook body is not valid JSON.")
	}

	normalized := brevoNormalizeEvent(evt.Event)
	span.SetAttributes(
		attribute.String("brevo.event", normalized),
		attribute.Bool("brevo.has_message_id", evt.MessageID != ""),
	)

	fn, known := brevoEventHandlers[normalized]
	if !known {
		// Brevo emits 'request', 'click', 'open', and a long tail of
		// engagement events. None of them are ledger-relevant; we
		// 200 + skip so Brevo doesn't retry. Counter labelled
		// "unhandled" so an operator alert can fire on cardinality
		// spikes (someone shipped a new Brevo event we should care
		// about).
		slog.Debug("webhook.brevo.unhandled_event",
			"event", normalized,
			"have_message_id", evt.MessageID != "",
		)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("unhandled").Inc()
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	if evt.MessageID == "" {
		// A documented event without a messageId can't be matched to a
		// ledger row. Log + 200 + skip (NEVER 404 — Brevo retries on
		// non-2xx). Counter so the operator alert key is stable.
		slog.Warn("webhook.brevo.missing_message_id",
			"event", normalized,
			"recipient_masked", models.MaskEmail(evt.Email),
		)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("missing_message_id").Inc()
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "skipped": true})
	}

	matched, err := fn(ctx, h, evt)
	if err != nil {
		// True DB outage — Brevo SHOULD retry. Return 500. The handler
		// itself doesn't classify the error; the caller does.
		slog.Error("webhook.brevo.update_failed",
			"event", normalized,
			"message_id", evt.MessageID,
			"recipient_masked", models.MaskEmail(evt.Email),
			"error", err,
		)
		metrics.BrevoWebhookEventsTotal.WithLabelValues("error").Inc()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"ok":    false,
			"error": "internal_error",
		})
	}

	// The event was processed. Counter label is the normalized event
	// type — useful in NR ("show me hard_bounce rate over 24h") and
	// for Prometheus. Cardinality is bounded by brevoDocumentedEvents
	// + the "unhandled"/"unauthorized"/... admin labels above.
	metrics.BrevoWebhookEventsTotal.WithLabelValues(normalized).Inc()

	if !matched {
		// The event was valid but no forwarder_sent row matched the
		// messageId. Logged WARN (already) — see handler bodies.
		// 200 OK with matched=false so the operator can scrape the
		// response in Brevo's dashboard log to see "Brevo received,
		// instanode persisted nothing."
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"ok":      true,
			"matched": false,
			"event":   normalized,
		})
	}
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"ok":      true,
		"matched": true,
		"event":   normalized,
	})
}

// handleBrevoDelivered updates classification='delivered' AND stamps
// delivered_at = now() on the matching row. delivered_at uses
// GREATEST so a re-delivery of the same event doesn't bump the
// timestamp.
func handleBrevoDelivered(ctx context.Context, h *BrevoTransactionalWebhookHandler, evt brevoTransactionalEvent) (bool, error) {
	// bug bash #6: a 'delivered' event must NOT clobber a TERMINAL negative
	// outcome. Brevo delivers webhook events out of order, so a late
	// 'delivered' (SMTP-accept) can arrive after a 'bounced_*' / 'rejected' /
	// 'complaint' / 'unsubscribed' has already been recorded — overwriting the
	// ledger's truth surface (rule 12). The guard preserves terminal classes.
	res, err := h.db.ExecContext(ctx, `
		UPDATE forwarder_sent
		   SET classification = $1,
		       delivered_at   = COALESCE(GREATEST(delivered_at, NOW()), NOW())
		 WHERE provider = $2
		   AND provider_id = $3
		   AND classification NOT IN ($4, $5, $6, $7, $8)
	`, LedgerClassDelivered, brevoProviderName, evt.MessageID,
		LedgerClassBouncedHard, LedgerClassBouncedSoft, LedgerClassRejected,
		LedgerClassComplaint, LedgerClassUnsubscribed)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		slog.Info("webhook.brevo.delivered",
			"message_id", evt.MessageID,
			"recipient_masked", models.MaskEmail(evt.Email),
			"rows_updated", n,
		)
		return true, nil
	}
	// n == 0: either no row matches this messageId, OR the row exists but
	// already holds a terminal class we intentionally preserved. Distinguish
	// the two so a real-but-terminal message isn't mislabeled "unknown".
	var existingClass string
	qErr := h.db.QueryRowContext(ctx, `
		SELECT classification FROM forwarder_sent
		 WHERE provider = $1 AND provider_id = $2
		 LIMIT 1
	`, brevoProviderName, evt.MessageID).Scan(&existingClass)
	if qErr == sql.ErrNoRows {
		warnUnknownBrevoMessage(ctx, evt, brevoEventDelivered)
		return false, nil
	}
	if qErr != nil {
		return false, qErr
	}
	// Row matched but a terminal classification was kept — this IS a known
	// message (matched=true), we just don't downgrade the outcome.
	slog.Info("webhook.brevo.delivered_kept_terminal",
		"message_id", evt.MessageID,
		"recipient_masked", models.MaskEmail(evt.Email),
		"kept_classification", existingClass,
		"note", "out-of-order delivered ignored — terminal class preserved (bug bash #6)",
	)
	return true, nil
}

// makeClassUpdater returns a brevoEventHandler that sets classification
// to the supplied terminal class without touching delivered_at — only
// the 'delivered' event ever sets delivered_at. Used for hard_bounce,
// soft_bounce, blocked, complaint, deferred, unsubscribed, error.
func makeClassUpdater(class string) brevoEventHandler {
	return func(ctx context.Context, h *BrevoTransactionalWebhookHandler, evt brevoTransactionalEvent) (bool, error) {
		res, err := h.db.ExecContext(ctx, `
			UPDATE forwarder_sent
			   SET classification = $1
			 WHERE provider = $2
			   AND provider_id = $3
		`, class, brevoProviderName, evt.MessageID)
		if err != nil {
			return false, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, err
		}
		if n == 0 {
			warnUnknownBrevoMessage(ctx, evt, class)
			return false, nil
		}
		slog.Info("webhook.brevo.classified",
			"class", class,
			"message_id", evt.MessageID,
			"recipient_masked", models.MaskEmail(evt.Email),
			"reason", evt.Reason,
			"rows_updated", n,
		)
		return true, nil
	}
}

// warnUnknownBrevoMessage logs the (benign-but-noteworthy) case of a
// Brevo event whose messageId doesn't match any row. Common causes:
//   * pre-receiver legacy sends (provider_id='audit-<uuid>' placeholder)
//   * staging/prod cluster crosstalk
//   * Brevo dashboard test sends
// All three are non-actionable in the steady state but worth surfacing
// if the rate spikes (might indicate a misconfigured webhook URL).
func warnUnknownBrevoMessage(ctx context.Context, evt brevoTransactionalEvent, classification string) {
	_ = ctx // reserved for future span attribute attachment
	slog.Warn("webhook.brevo.unknown_message_id",
		"event_class", classification,
		"message_id", evt.MessageID,
		"recipient_masked", models.MaskEmail(evt.Email),
		"reason", evt.Reason,
		"note", "no forwarder_sent row matched provider_id — pre-receiver legacy row / cross-cluster traffic / Brevo dashboard test",
	)
}

// MaskedReceivePath returns the receive path with the secret segment
// rendered as ":secret" so route-table dumps don't leak the
// configured secret. Used by router.go's pretty-printer.
func (h *BrevoTransactionalWebhookHandler) MaskedReceivePath() string {
	return brevoWebhookRoutePath
}

// BrevoDocumentedEventsForTest exposes the closed list of Brevo events
// to the _test package so the registry-iterating coverage test
// (TestBrevoTxWebhook_EveryDocumentedEventHasHandler) can fail in the
// same PR that adds a new event to brevoDocumentedEvents without a
// matching entry in brevoEventHandlers. Only intended for tests —
// production callers must never depend on this surface.
func BrevoDocumentedEventsForTest() []string {
	out := make([]string, len(brevoDocumentedEvents))
	copy(out, brevoDocumentedEvents)
	return out
}

// ── Ledger inspection (used by tests + future support tooling) ─────────────

// LookupForwarderSentByProviderID fetches the row keyed by (provider,
// provider_id). Returns sql.ErrNoRows if there is no match. Public so
// e2e tests under -tags e2e can verify the row update after a synthetic
// webhook POST.
func LookupForwarderSentByProviderID(ctx context.Context, db *sql.DB, providerID string) (BrevoForwarderRow, error) {
	const q = `
		SELECT audit_id,
		       sent_at,
		       provider,
		       provider_id,
		       recipient,
		       template_kind,
		       classification,
		       delivered_at
		  FROM forwarder_sent
		 WHERE provider = $1
		   AND provider_id = $2
		 LIMIT 1
	`
	var row BrevoForwarderRow
	var delivered sql.NullTime
	err := db.QueryRowContext(ctx, q, brevoProviderName, providerID).Scan(
		&row.AuditID, &row.SentAt, &row.Provider, &row.ProviderID,
		&row.Recipient, &row.TemplateKind, &row.Classification, &delivered,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return row, sql.ErrNoRows
	}
	if err != nil {
		return row, err
	}
	if delivered.Valid {
		row.DeliveredAt = &delivered.Time
	}
	return row, nil
}

// BrevoForwarderRow is the in-memory projection of one forwarder_sent
// row. Public so tests can introspect the update path.
type BrevoForwarderRow struct {
	AuditID        string
	SentAt         time.Time
	Provider       string
	ProviderID     string
	Recipient      string
	TemplateKind   string
	Classification string
	DeliveredAt    *time.Time // nil until a 'delivered' event arrives
}
