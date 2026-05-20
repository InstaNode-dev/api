package handlers

// webhook.go — POST /webhook/new, POST /webhook/receive/:token, GET /api/v1/webhooks/:token/requests
//
// The webhook service is stateless — no gRPC provisioner needed.
// Received payloads are stored in Redis with a TTL and served back via the list API.
//
// Response shape for POST /webhook/new:
//
//	{
//	  "ok":          true,
//	  "id":          "<uuid>",
//	  "token":       "<uuid>",
//	  "receive_url": "https://instant.dev/webhook/receive/<token>",
//	  "tier":        "anonymous",
//	  "limits":      {"requests_stored": 100, "expires_in": "24h"},
//	  "note":        "...",
//	  "expires_at":  "..."
//	}

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/common/resourcestatus"
	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/safego"
	"instant.dev/internal/urls"
)

const (
	// webhookAnonTTL is the Redis TTL for anonymous webhook payloads.
	webhookAnonTTL = 24 * time.Hour

	// webhookAuthTTL is the Redis TTL for authenticated webhook payloads.
	webhookAuthTTL = 7 * 24 * time.Hour

	// webhookMaxBodyBytes is the hard ceiling on stored body size for
	// /webhook/receive/:token. Set explicitly so the receiver enforces
	// 1 MiB even when the ambient Fiber config or ingress raises it.
	// Bodies larger than this return 413 payload_too_large.
	//
	// Reconciles BugBash Q30: ingress allowed 100MB, docs claimed 1MB,
	// Fiber default was 4MB — the actual stored cap was effectively
	// "whatever made it through ingress minus our slice." Now uniform.
	webhookMaxBodyBytes = 1 << 20

	// webhookRedactedValue is what every sensitive header value is
	// rewritten to before storage. Keeping the KEY visible lets a debugging
	// agent see "yes an Authorization header WAS attached" without the
	// secret itself reaching Redis or the GET /requests response.
	webhookRedactedValue = "[REDACTED]"

	// webhookHMACHeader is the header an HMAC-locked webhook expects.
	// Standard "sha256=<hex>" GitHub-style value.
	webhookHMACHeader = "X-Hub-Signature-256"

	// webhookRotationHeader is set on the receive response when the
	// 101st (i.e. cap+1) payload arrived and the ring buffer evicted
	// the oldest entry. Real webhook senders (Stripe, GitHub, Twilio)
	// ignore extra response headers, but a human or AI agent watching
	// the receiver during development sees rotation explicitly instead
	// of silently losing the earliest payload.
	webhookRotationHeader = "X-Webhook-Rotated"

	// webhookIdempotencyHeader is the per-receive idempotency key.
	// Distinct from the generic Idempotency middleware's header because
	// the receive path is signed by senders like Stripe that already
	// emit their own X-Idempotency-Key for retries — we honour theirs
	// directly instead of forcing them to pick a different name.
	webhookIdempotencyHeader = "X-Idempotency-Key"
)

// sensitiveHeaders names the lower-case header keys whose values must be
// rewritten to [REDACTED] before the captured request is persisted. Keys
// are kept in canonical (textproto.CanonicalMIMEHeaderKey) form so the
// match is case-insensitive against caller input. This denylist is the
// fix for BugBash #119 / #S7 — every value in this set was previously
// stored verbatim in Redis and returned by GET /api/v1/webhooks/:token/requests,
// so anyone holding the receive URL could exfiltrate the sender's
// credentials. The key is preserved (only the value is overwritten) so a
// developer debugging "did my sender attach Authorization?" still sees
// the answer.
var sensitiveHeaders = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"X-Api-Key":           true,
	"X-Auth-Token":        true,
}

// webhookMaxStored returns the request cap for a given tier from plans.yaml.
// Returns 100 as a safe floor when the Registry returns 0 or a negative value
// other than -1 (unlimited). -1 is clamped to 10_000 for the Redis LTRIM call.
func (h *WebhookHandler) webhookMaxStored(tier string) int64 {
	n := h.plans.StorageLimitMB(tier, "webhook") // reuses the webhook_requests_stored field
	if n == -1 {
		return 10_000 // unlimited tier — keep at most 10k in Redis
	}
	if n <= 0 {
		return 100 // safe floor
	}
	return int64(n)
}

// WebhookHandler handles POST /webhook/new, POST /webhook/receive/:token,
// and GET /api/v1/webhooks/:token/requests.
type WebhookHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	cfg   *config.Config
	plans *plans.Registry
	provisionHelper
}

// NewWebhookHandler constructs a WebhookHandler.
func NewWebhookHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config, p *plans.Registry) *WebhookHandler {
	return &WebhookHandler{
		db:              db,
		rdb:             rdb,
		cfg:             cfg,
		plans:           p,
		provisionHelper: newProvisionHelper(db, rdb, cfg, p),
	}
}

// receiveURL builds the public receive URL for a given token.
// baseURL must be a fixed, server-controlled value — see webhookReceiveBaseURL.
func receiveURL(baseURL, token string) string {
	return fmt.Sprintf("%s/webhook/receive/%s", baseURL, token)
}

// webhookReceiveBaseURL returns the canonical base URL for receive URLs.
//
// The receive URL is encrypted and persisted (connection_url), so it MUST NOT
// be derived from the client-controllable Host / X-Forwarded-* headers —
// middleware/auth.go documents the same rule for the audience canonical URL.
// An attacker who controls those headers on the provisioning request could
// otherwise pin every future receiver to a host they own.
//
// Resolution: API_PUBLIC_URL when configured (production), else the compiled-in
// public API base. Only in non-production environments do we fall back to
// c.BaseURL() so local dev (http://localhost:8080) keeps working.
func (h *WebhookHandler) webhookReceiveBaseURL(c *fiber.Ctx) string {
	if h.cfg != nil && h.cfg.APIPublicURL != "" {
		return h.cfg.APIPublicURL
	}
	if h.cfg != nil && h.cfg.Environment != "production" {
		return c.BaseURL()
	}
	return urls.PublicAPIBase
}

// webhookRedisKey returns the per-request Redis key.
func webhookRedisKey(token, reqID string) string {
	return fmt.Sprintf("wh:%s:%s", token, reqID)
}

// webhookListKey returns the list Redis key for a token.
func webhookListKey(token string) string {
	return fmt.Sprintf("wh:list:%s", token)
}

// webhookAnonLimits returns the limits map for anonymous webhook resources.
// requests_stored is sourced through webhookMaxStored — the SAME accessor the
// LTRIM enforcement path uses — so the advertised cap and the cap actually
// enforced never drift (a plans.yaml -1/0 edge previously surfaced one raw
// number here and a different clamped one to Redis).
func (h *WebhookHandler) webhookAnonLimits() fiber.Map {
	return fiber.Map{
		"requests_stored": h.webhookMaxStored(tierAnonymous),
		"expires_in":      "24h",
	}
}

// NewWebhook handles POST /webhook/new.
func (h *WebhookHandler) NewWebhook(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("webhook") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Webhook provisioning is coming soon. Sign up at "+urls.StartURLPrefix+" to be notified.")
	}

	start := time.Now()
	ctx := c.UserContext()
	fp := middleware.GetFingerprint(c)
	country := middleware.GetGeoCountry(c)
	vendor := middleware.GetCloudVendor(c)
	requestID := middleware.GetRequestID(c)

	var body provisionRequestBody
	if err := parseProvisionBody(c, &body); err != nil {
		return err
	}
	cleanName, nameErr := requireName(c, body.Name)
	if nameErr != nil {
		return nameErr
	}
	body.Name = cleanName

	env, envErr := resolveEnv(c, body.Env)
	if envErr != nil {
		return envErr
	}

	// ── Authenticated path ───────────────────────────────────────────────────────
	if teamIDStr := middleware.GetTeamID(c); teamIDStr != "" {
		return h.newWebhookAuthenticated(c, teamIDStr, fp, country, vendor, requestID, body.Name, env, start)
	}

	// ── Anonymous path ───────────────────────────────────────────────────────────
	limitExceeded, err := h.checkProvisionLimit(ctx, fp)
	if err != nil {
		slog.Error("webhook.new.provision_limit_check_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("provision_limit").Inc()
	}

	if limitExceeded {
		existing, err := models.GetActiveResourceByFingerprintType(ctx, h.db, fp, "webhook", env)
		if err != nil {
			// P1-A: cross-service daily-cap fallback — see db.go for rationale.
			if _, anyErr := models.GetActiveResourceByFingerprint(ctx, h.db, fp, env); anyErr == nil {
				metrics.FingerprintAbuseBlocked.Inc()
				return respondError(c, fiber.StatusTooManyRequests, "provision_limit_reached",
					"Daily anonymous provisioning limit reached for this network. Sign up at "+urls.StartURLPrefix)
			}
			// F2 TOCTOU fix (2026-05-19): over-cap caller, both lookups missed
			// (burst winners not yet committed). Hard-deny — never fall through
			// to a fresh provision. See denyProvisionOverCap for the full rationale.
			return h.denyProvisionOverCap(c, fp, "webhook")
		}
		if err == nil {
			jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "webhook", []string{existing.Token.String()})
			if jwtErr == nil && jti != "" {
				if evErr := h.createOnboardingEvent(ctx, fp, jti, existing.Token); evErr != nil {
					slog.Error("webhook.new.onboarding_event_failed_limit_path", "error", evErr, "request_id", requestID)
				}
			}
			upgradeURL := ""
			if jwtToken != "" {
				upgradeURL = urls.UpgradeStartURL(jwtToken)
				c.Set("X-Instant-Upgrade", upgradeURL)
			}
			metrics.FingerprintAbuseBlocked.Inc()

			// Decrypt the stored connection_url (the receive_url) to return it in plaintext.
			url := h.decryptWebhookURL(existing.ConnectionURL.String, requestID)

			resp := fiber.Map{
				"ok": true,
				"id": existing.ID.String(),
				// T19 P1-6 / T14 (BugHunt 2026-05-20): echo `name`.
				"name":        existing.Name.String,
				"token":       existing.Token.String(),
				"receive_url": url,
				"tier":        existing.Tier,
				"env":         existing.Env,
				"limits":      h.webhookAnonLimits(),
				"note":        limitExceededNote(upgradeURL, existing.ExpiresAt.Time),
				"upgrade":     upgradeURL,
				"upgrade_jwt": jwtToken,
			}
			if existing.ExpiresAt.Valid {
				// P2-03: emit RFC3339 (not the default RFC3339Nano of a raw
				// time.Time) so expires_at has one wire shape across every
				// provisioning endpoint — matches storage.go.
				resp["expires_at"] = existing.ExpiresAt.Time.Format(time.RFC3339)
			}
			return respondOK(c, resp)
		}
	}

	// Free-tier recycle gate (see provision_helper.go for rationale).
	if h.recycleGate(c, fp, "webhook") {
		return nil
	}

	expiresAt := time.Now().UTC().Add(24 * time.Hour)
	tokenStr := ""

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		ResourceType:     "webhook",
		Name:             body.Name,
		Tier:             "anonymous",
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        &expiresAt,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("webhook.new.create_resource_failed",
			"error", err, "fingerprint", fp, "request_id", requestID)
		middleware.RecordProvisionFail("webhook", middleware.ProvisionFailInternal)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision webhook resource")
	}
	tokenStr = resource.Token.String()

	// Build the receive URL. The base is a fixed server-controlled value —
	// never the client Host header.
	rURL := receiveURL(h.webhookReceiveBaseURL(c), tokenStr)
	provCtx, span := h.startProvisionSpan(ctx, "webhook", "anonymous", "", fp, tokenStr)
	// MR-P0-2 / MR-P0-3: encrypt + persist the receive URL and flip the row
	// pending→active. A persistence failure returns 503, never a 201 with an
	// unrecoverable receive URL. Webhook is status-only — there is no backend
	// object to tear down beyond the soft-deleted row (cleanup=nil).
	finErr := h.finalizeProvision(provCtx, resource, rURL, "", "", requestID, "webhook.new", nil)
	finishProvisionSpan(span, finErr)
	if finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("webhook", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist webhook resource")
	}

	jwtToken, jti, jwtErr := h.issueOnboardingJWT(ctx, fp, country, vendor, "webhook", []string{tokenStr})
	if jwtErr != nil {
		slog.Error("webhook.new.jwt_issue_failed", "error", jwtErr, "request_id", requestID)
	}
	if jti != "" {
		if evErr := h.createOnboardingEvent(ctx, fp, jti, resource.Token); evErr != nil {
			slog.Error("webhook.new.onboarding_event_failed", "error", evErr, "request_id", requestID)
		}
	}

	upgradeURL := ""
	if jwtToken != "" {
		upgradeURL = urls.UpgradeStartURL(jwtToken)
		c.Set("X-Instant-Upgrade", upgradeURL)
	}

	slog.Info("provision.success",
		"service", "webhook",
		"token", tokenStr,
		"name", resource.Name.String,
		"fingerprint", fp,
		"cloud_vendor", vendor,
		"tier", "anonymous",
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("webhook", "anonymous").Inc()
	middleware.RecordProvisionSuccess("webhook")
	metrics.ConversionFunnel.WithLabelValues("provision").Inc()

	if markErr := h.markRecycleSeen(ctx, fp); markErr != nil {
		slog.Warn("webhook.new.mark_recycle_seen_failed",
			"error", markErr, "fingerprint", fp, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("recycle_mark").Inc()
	}

	return respondCreated(c, fiber.Map{
		"ok":   true,
		"id":   resource.ID.String(),
		// T19 P1-6 / T14 (BugHunt 2026-05-20): echo `name` so the
		// mandatory-input field is round-trippable. Was previously
		// write-only — callers had no way to read back the label they set.
		"name":        resource.Name.String,
		"token":       tokenStr,
		"receive_url": rURL,
		"tier":        "anonymous",
		"env":         resource.Env,
		"limits":      h.webhookAnonLimits(),
		"note":        upgradeNote(upgradeURL),
		"upgrade":     upgradeURL,
		"upgrade_jwt": jwtToken,
		// P2-03: RFC3339 to match storage.go and the webhook dedup branch —
		// one wire shape for expires_at across all provisioning endpoints.
		"expires_at": expiresAt.Format(time.RFC3339),
	})
}

// newWebhookAuthenticated handles the authenticated path for POST /webhook/new.
func (h *WebhookHandler) newWebhookAuthenticated(
	c *fiber.Ctx, teamIDStr, fp, country, vendor, requestID, name string, env string, start time.Time,
) error {
	ctx := c.UserContext()
	teamUUID, err := parseTeamID(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team", "Team ID in token is not a valid UUID")
	}
	team, err := models.GetTeamByID(ctx, h.db, teamUUID)
	if err != nil {
		slog.Error("webhook.new.team_lookup_failed", "error", err, "team_id", teamIDStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "team_lookup_failed", "Failed to look up team")
	}

	resource, err := models.CreateResource(ctx, h.db, models.CreateResourceParams{
		TeamID:           &teamUUID,
		ResourceType:     "webhook",
		Name:             name,
		Tier:             team.PlanTier,
		Env:              env,
		Fingerprint:      fp,
		CloudVendor:      vendor,
		CountryCode:      country,
		ExpiresAt:        nil,
		CreatedRequestID: requestID,
	})
	if err != nil {
		slog.Error("webhook.new.create_resource_failed_auth",
			"error", err, "team_id", teamIDStr, "request_id", requestID)
		middleware.RecordProvisionFail("webhook", middleware.ProvisionFailInternal)
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "Failed to provision webhook resource")
	}

	// Best-effort audit event; failures must never block the provision.
	safego.Go("webhook.bg", func() {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:       teamUUID,
			Actor:        "agent",
			Kind:         "provision",
			ResourceType: "webhook",
			ResourceID:   uuid.NullUUID{UUID: resource.ID, Valid: true},
			Summary:      "agent provisioned <strong>webhook</strong> <code>" + resource.Token.String()[:8] + "</code>",
		})
	})

	tokenStr := resource.Token.String()
	rURL := receiveURL(h.webhookReceiveBaseURL(c), tokenStr)

	provCtx, span := h.startProvisionSpan(ctx, "webhook", team.PlanTier, teamIDStr, fp, tokenStr)
	// MR-P0-2 / MR-P0-3: encrypt + persist the receive URL and flip the row
	// pending→active. A persistence failure returns 503, never a 201 with an
	// unrecoverable receive URL.
	finErr := h.finalizeProvision(provCtx, resource, rURL, "", "", requestID, "webhook.new.auth", nil)
	finishProvisionSpan(span, finErr)
	if finErr != nil {
		metrics.ProvisionFailures.WithLabelValues("webhook", "persist_error").Inc()
		return respondProvisionFailed(c, finErr, "Failed to persist webhook resource")
	}

	slog.Info("provision.success",
		"service", "webhook",
		"token", tokenStr,
		"name", resource.Name.String,
		"team_id", teamIDStr,
		"tier", team.PlanTier,
		"duration_ms", time.Since(start).Milliseconds(),
		"request_id", requestID,
	)
	metrics.ProvisionsTotal.WithLabelValues("webhook", team.PlanTier).Inc()
	middleware.RecordProvisionSuccess("webhook")

	return respondCreated(c, fiber.Map{
		"ok": true,
		"id": resource.ID.String(),
		// T19 P1-6 / T14 (BugHunt 2026-05-20): echo `name`.
		"name":        resource.Name.String,
		"token":       tokenStr,
		"receive_url": rURL,
		"tier":        team.PlanTier,
		"env":         resource.Env,
		"limits": fiber.Map{
			"requests_stored": h.webhookMaxStored(team.PlanTier),
		},
	})
}

// Receive handles ANY HTTP method against /webhook/receive/:token — stores
// the incoming request in Redis. This endpoint requires no platform
// authentication; the resource token in the URL is itself the address.
//
// Registered with app.All so verification-challenge flows (Slack URL
// verify uses GET, some senders use PUT/DELETE) reach the handler instead
// of bouncing off a 405 (BugBash #Q29).
//
// Security posture (BugBash Wave FIX-C):
//   - Sensitive header values are rewritten to [REDACTED] before storage
//     so GET /api/v1/webhooks/:token/requests cannot leak the sender's
//     Authorization / Cookie / API key (#119 / #S7).
//   - Optional HMAC verification (X-Hub-Signature-256) when the resource
//     has a non-NULL hmac_secret. Unset secret = back-compat open
//     receiver (existing tokens keep working).
//   - Body size capped at webhookMaxBodyBytes (1 MiB) explicitly; over
//     limit returns 413 instead of silently truncating (#Q30).
//   - Query string captured (RFC 3986: everything after '?', excluding
//     fragment) so flows that encode shop/event ids in the URL no longer
//     lose that signal (#123 / #Q33).
//   - All duplicate headers preserved (map[string][]string) instead of
//     collapsing to the last value (#Q32).
//   - X-Idempotency-Key honoured: replays return the cached request
//     payload without writing a new ring-buffer entry (#Q28).
//   - X-Webhook-Rotated header emitted on the response when this payload
//     evicted the oldest stored request (#Q34).
//   - Per-request Redis Set/Get write removed — was a dead write never
//     read by ListRequests (#Q31).
func (h *WebhookHandler) Receive(c *fiber.Ctx) error {
	if !h.cfg.IsServiceEnabled("webhook") {
		return respondError(c, fiber.StatusServiceUnavailable, "service_disabled",
			"Webhook service is not enabled.")
	}

	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)
	tokenStr := c.Params("token")

	tokenUUID, err := uuid.Parse(tokenStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token must be a valid UUID")
	}

	// Look up the resource to ensure it exists and is active.
	resource, err := models.GetResourceByToken(ctx, h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
		}
		slog.Error("webhook.receive.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up webhook")
	}

	// GetResourceByToken selects by token only — a postgres/redis/queue/etc
	// token would pass. Reject anything that is not a webhook so the receiver
	// can never be addressed with another service's token (404, same as a
	// genuinely missing token — never confirm the token belongs to a
	// different resource type).
	if resource.ResourceType != models.ResourceTypeWebhook {
		return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
	}

	if resStatus, _ := resourcestatus.Parse(resource.Status); !resStatus.IsActive() {
		return respondError(c, fiber.StatusGone, "webhook_inactive", "This webhook token is no longer active")
	}

	// P1-C: reject an expired webhook. The status check above only catches
	// rows the worker has already swept; an anonymous webhook past its 24h TTL
	// can still be status='active' until the next worker tick. Each Receive
	// re-extends the Redis-list TTL, so without this check an expired webhook
	// keeps accepting (and persisting) payloads indefinitely.
	if resource.ExpiresAt.Valid && resourcestatus.IsPastTTL(resource.ExpiresAt.Time, time.Now()) {
		return respondError(c, fiber.StatusGone, "webhook_expired",
			"This webhook token has expired. Sign up to keep your webhook alive.")
	}

	// ── Body size enforcement ───────────────────────────────────────────────
	// c.Body() returns the buffered body from fasthttp. We check length BEFORE
	// reading further so a 1.5MiB body is rejected with 413 instead of being
	// silently truncated (BugBash #Q30: ingress allows 100MB, fiber default
	// allowed 4MB, docs claimed 1MB — none of those agreed with reality).
	rawBody := c.Body()
	if len(rawBody) > webhookMaxBodyBytes {
		return respondError(c, fiber.StatusRequestEntityTooLarge, "payload_too_large",
			fmt.Sprintf("Webhook payload exceeds the %d byte limit", webhookMaxBodyBytes))
	}

	// ── Optional HMAC verification (BugBash #122) ──────────────────────────
	// When the resource has a non-NULL hmac_secret, every incoming request
	// MUST carry an X-Hub-Signature-256 header whose hex digest matches
	// HMAC-SHA256(secret, body). NULL secret = back-compat (every existing
	// token keeps working without re-provisioning).
	hmacSecret, hmacErr := models.GetWebhookHMACSecret(ctx, h.db, resource.ID)
	if hmacErr != nil {
		slog.Error("webhook.receive.hmac_lookup_failed",
			"error", hmacErr, "token", tokenStr, "request_id", requestID)
		// Fail open on lookup errors — the column may not exist yet on a
		// stale schema, and blocking a real webhook because we couldn't
		// SELECT the secret column is the wrong default.
		hmacSecret = ""
	}
	if hmacSecret != "" {
		sig := c.Get(webhookHMACHeader)
		if !verifyWebhookHMAC(hmacSecret, rawBody, sig) {
			slog.Warn("webhook.receive.hmac_mismatch",
				"token", tokenStr,
				"has_signature", sig != "",
				"request_id", requestID,
			)
			metrics.RedisErrors.WithLabelValues("webhook_hmac_mismatch").Inc()
			return respondError(c, fiber.StatusUnauthorized, "invalid_signature",
				"Webhook signature does not match the configured HMAC secret")
		}
	}

	// ── Idempotency replay (BugBash #Q28) ──────────────────────────────────
	// If the caller sent X-Idempotency-Key, dedup on (token, key). A cached
	// response is returned verbatim — we never write a second ring-buffer
	// entry for the same (token, key) tuple within the TTL. Redis errors
	// fail open — an outage must not block the sender.
	idemKey := strings.TrimSpace(c.Get(webhookIdempotencyHeader))
	if idemKey != "" {
		if cached, ok := h.lookupIdempotentReceive(ctx, tokenStr, idemKey); ok {
			return c.JSON(cached)
		}
	}

	// ── Capture request envelope ───────────────────────────────────────────
	// Build a method/path/query/headers/body record. Headers map to
	// []string so a sender that sends two of the same key (e.g.
	// two `Set-Cookie` headers, or `Forwarded` chained through a proxy)
	// no longer collapses to "the last one wins" (BugBash #Q32).
	headers := captureHeaders(c)
	queryString := string(c.Request().URI().QueryString())

	reqID := uuid.New().String()
	receivedAt := time.Now().UTC()

	payload := map[string]any{
		"id":          reqID,
		"method":      string(c.Request().Header.Method()),
		"path":        string(c.Request().URI().Path()),
		"query":       queryString,
		"headers":     headers,
		"body":        string(rawBody),
		"received_at": receivedAt.Format(time.RFC3339),
	}

	payloadBytes, marshalErr := json.Marshal(payload)
	if marshalErr != nil {
		slog.Error("webhook.receive.marshal_failed",
			"error", marshalErr, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Failed to store request")
	}

	// Determine TTL based on tier. "anonymous" (pre-claim) and "free"
	// (claimed-but-unpaid) share the short 24h TTL — pay-from-day-one
	// means free-tier webhooks expire on the same clock as anonymous ones.
	// Anything paid (hobby/pro/team/growth) gets the longer authed TTL.
	ttl := webhookAnonTTL
	if resource.Tier != "anonymous" && resource.Tier != "free" {
		ttl = webhookAuthTTL
	}

	listKey := webhookListKey(tokenStr)
	maxStored := h.webhookMaxStored(resource.Tier)

	// Snapshot the pre-push length so we can detect ring-buffer rotation
	// (BugBash #Q34). LPush then LLen would race against concurrent
	// receives, but the length check is best-effort observability —
	// occasional miscounts here just mean a rotation event is missed in
	// the response header, not a correctness bug.
	preLen, lenErr := h.rdb.LLen(ctx, listKey).Result()
	if lenErr != nil {
		preLen = -1 // unknown
	}

	pipe := h.rdb.Pipeline()
	pipe.LPush(ctx, listKey, string(payloadBytes))
	pipe.LTrim(ctx, listKey, 0, maxStored-1)
	pipe.Expire(ctx, listKey, ttl)
	if _, pipeErr := pipe.Exec(ctx); pipeErr != nil {
		slog.Error("webhook.receive.redis_store_failed",
			"error", pipeErr, "token", tokenStr, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("webhook_store").Inc()
		// Fail open — don't block the sender even if Redis is down.
	}

	// Cache the response for idempotency replay (best-effort).
	respPayload := fiber.Map{"ok": true, "id": reqID}
	if idemKey != "" {
		h.storeIdempotentReceive(ctx, tokenStr, idemKey, respPayload, ttl)
	}

	// Set rotation header when this push evicted an entry. Pre-len == cap
	// means LPush + LTrim dropped one off the tail. Bump the metric so NR
	// can chart "tokens hitting their ring-buffer cap" — typically signals
	// the user needs to upgrade.
	if preLen >= 0 && preLen >= maxStored {
		c.Set(webhookRotationHeader, tokenStr)
		slog.Info("webhook.receive.rotation",
			"token", tokenStr,
			"tier", resource.Tier,
			"max_stored", maxStored,
			"request_id", requestID,
		)
		metrics.RedisErrors.WithLabelValues("webhook_rotation").Inc()
	}

	slog.Info("webhook.receive.stored",
		"token", tokenStr,
		"request_id", reqID,
		"method", string(c.Request().Header.Method()),
		"tier", resource.Tier,
	)

	return c.JSON(respPayload)
}

// captureHeaders reads every header from the incoming request, redacts
// sensitive values, and groups duplicate keys. Returns map[string][]string
// so a payload that arrived with two `Set-Cookie` headers preserves both
// (BugBash #Q32). Sensitive header values (Authorization, Cookie, ...) are
// rewritten to [REDACTED] — the key stays so an agent can see "yes a
// credential WAS attached" without the actual secret reaching storage.
func captureHeaders(c *fiber.Ctx) map[string][]string {
	headers := make(map[string][]string)
	c.Request().Header.VisitAll(func(key, value []byte) {
		canon := textproto.CanonicalMIMEHeaderKey(string(key))
		v := string(value)
		if sensitiveHeaders[canon] {
			v = webhookRedactedValue
		}
		headers[canon] = append(headers[canon], v)
	})
	return headers
}

// verifyWebhookHMAC constant-time-compares the expected HMAC-SHA256(body)
// against the X-Hub-Signature-256 header. Header format is
// "sha256=<hex>" (GitHub convention). Returns false if the header is
// missing, malformed, or its digest does not match.
func verifyWebhookHMAC(secret string, body []byte, header string) bool {
	if header == "" {
		return false
	}
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got, decErr := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if decErr != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	return hmac.Equal(got, want)
}

// webhookIdempotencyKey returns the Redis key used to cache a previous
// receive response for replay. Scoped per (token, raw-idempotency-key)
// so the same key sent to two different webhook tokens cannot collide.
// The raw key is hashed so an attacker that compromises Redis cannot
// reverse keys back to whatever opaque value the sender chose.
func webhookIdempotencyKey(token, key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("wh:idem:%s:%s", token, hex.EncodeToString(h[:]))
}

// lookupIdempotentReceive checks for a cached response from a previous
// receive with the same idempotency key. Fail-open on Redis errors
// (treat as a miss) — an outage must not block real webhook traffic.
func (h *WebhookHandler) lookupIdempotentReceive(ctx context.Context, token, key string) (fiber.Map, bool) {
	raw, err := h.rdb.Get(ctx, webhookIdempotencyKey(token, key)).Result()
	if err != nil {
		return nil, false
	}
	var cached fiber.Map
	if jsonErr := json.Unmarshal([]byte(raw), &cached); jsonErr != nil {
		return nil, false
	}
	return cached, true
}

// storeIdempotentReceive persists the receive response so a retry with
// the same X-Idempotency-Key replays instead of writing a fresh entry.
// TTL matches the resource's stored-payload TTL — when the body it
// refers to ages out, the idempotency cache ages out too, so an old
// key cannot replay against a now-empty ring buffer.
func (h *WebhookHandler) storeIdempotentReceive(ctx context.Context, token, key string, resp fiber.Map, ttl time.Duration) {
	payload, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if setErr := h.rdb.Set(ctx, webhookIdempotencyKey(token, key), payload, ttl).Err(); setErr != nil {
		metrics.RedisErrors.WithLabelValues("webhook_idem_store").Inc()
	}
}

// ListRequests handles GET /api/v1/webhooks/:token/requests.
//
// Auth: the resource token in the URL is itself the credential — no session required.
// This makes the endpoint agent-friendly: whoever holds the token can read their payloads.
// Authenticated users additionally get access to team-owned webhooks by session.
func (h *WebhookHandler) ListRequests(c *fiber.Ctx) error {
	ctx := c.UserContext()
	requestID := middleware.GetRequestID(c)

	tokenStr := c.Params("token")
	tokenUUID, parseErr := uuid.Parse(tokenStr)
	if parseErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Token must be a valid UUID")
	}

	resource, err := models.GetResourceByToken(ctx, h.db, tokenUUID)
	if err != nil {
		var notFound *models.ErrResourceNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
		}
		slog.Error("webhook.list_requests.lookup_failed",
			"error", err, "token", tokenStr, "request_id", requestID)
		return respondError(c, fiber.StatusServiceUnavailable, "lookup_failed", "Failed to look up webhook")
	}

	// GetResourceByToken selects by token only — reject any non-webhook
	// resource so a postgres/redis/etc token cannot read this endpoint
	// (404, mirroring Receive).
	if resource.ResourceType != models.ResourceTypeWebhook {
		return respondError(c, fiber.StatusNotFound, "not_found", "Webhook token not found")
	}

	// P2 (BugBash 2026-05-18): reject a non-active webhook for consistency
	// with Receive. Receive rejects status != 'active' (suspended / deleted /
	// reaped) with 410; ListRequests must do the same — otherwise a suspended
	// webhook's stored payloads (which may carry credentials sent by the
	// upstream) stay readable through the public list API after the resource
	// has been quota-suspended.
	if resStatus, _ := resourcestatus.Parse(resource.Status); !resStatus.IsActive() {
		return respondError(c, fiber.StatusGone, "webhook_inactive",
			"This webhook token is no longer active")
	}

	// P1-C: reject an expired webhook for consistency with Receive — an expired
	// anonymous webhook's stored requests are about to be swept by the worker;
	// don't serve them as if the resource were still live.
	if resource.ExpiresAt.Valid && resourcestatus.IsPastTTL(resource.ExpiresAt.Time, time.Now()) {
		return respondError(c, fiber.StatusGone, "webhook_expired",
			"This webhook token has expired. Sign up to keep your webhook alive.")
	}

	// Authorization: token in the URL IS the credential (token == resource.Token).
	// If the caller also has a session, verify they own the team resource.
	// Anonymous resources (no team_id) are readable with just the token.
	if resource.TeamID.Valid {
		teamID, authErr := parseTeamID(middleware.GetTeamID(c))
		if authErr != nil || resource.TeamID.UUID != teamID {
			return respondError(c, fiber.StatusForbidden, "forbidden", "Valid session token required for team-owned webhooks")
		}
	}

	listKey := webhookListKey(tokenStr)
	items, redisErr := h.rdb.LRange(ctx, listKey, 0, -1).Result()
	if redisErr != nil {
		slog.Error("webhook.list_requests.redis_read_failed",
			"error", redisErr, "token", tokenStr, "request_id", requestID)
		metrics.RedisErrors.WithLabelValues("webhook_list").Inc()
		// Fail open — return empty list rather than 503.
		items = []string{}
	}

	// Decode each item from its JSON string back to a map for the response.
	requests := make([]map[string]any, 0, len(items))
	for _, item := range items {
		var m map[string]any
		if jsonErr := json.Unmarshal([]byte(item), &m); jsonErr != nil {
			slog.Warn("webhook.list_requests.decode_item_failed",
				"error", jsonErr, "token", tokenStr)
			continue
		}
		requests = append(requests, m)
	}

	return c.JSON(fiber.Map{
		"ok":       true,
		"requests": requests,
		"total":    len(requests),
	})
}

// storeEncryptedURL encrypts the receive URL and persists it as connection_url.
func (h *WebhookHandler) storeEncryptedURL(ctx context.Context, resourceID uuid.UUID, rURL, requestID string) error {
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		return fmt.Errorf("storeEncryptedURL: parse key: %w", err)
	}
	encrypted, err := crypto.Encrypt(aesKey, rURL)
	if err != nil {
		return fmt.Errorf("storeEncryptedURL: encrypt: %w", err)
	}
	if upErr := models.UpdateConnectionURL(ctx, h.db, resourceID, encrypted); upErr != nil {
		return fmt.Errorf("storeEncryptedURL: update: %w", upErr)
	}
	return nil
}

// decryptWebhookURL decrypts an AES-encrypted receive URL stored in the DB.
// Returns the ciphertext unchanged if decryption fails (fail open).
func (h *WebhookHandler) decryptWebhookURL(encrypted, requestID string) string {
	if encrypted == "" {
		return ""
	}
	aesKey, err := crypto.ParseAESKey(h.cfg.AESKey)
	if err != nil {
		slog.Error("webhook.decrypt_url.aes_key_parse_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	plain, err := crypto.Decrypt(aesKey, encrypted)
	if err != nil {
		slog.Error("webhook.decrypt_url.decrypt_failed", "error", err, "request_id", requestID)
		return encrypted
	}
	return plain
}
