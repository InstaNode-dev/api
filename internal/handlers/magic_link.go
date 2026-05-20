package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// magicLinkTTL is how long an emailed sign-in link remains valid.
// 15 minutes is long enough to survive an email-client preview round-trip
// and short enough that a leaked token is rarely useful.
const magicLinkTTL = 15 * time.Minute

// magicLinkEmailRateLimit is the maximum number of magic-link emails
// allowed per normalised email address per hour (A04 fix).
// Fail-open per CLAUDE.md convention 1: a Redis error never blocks the request.
const magicLinkEmailRateLimit = 5

// magicLinkEmailRateLimitWindow is the rolling window for the per-email counter.
const magicLinkEmailRateLimitWindow = time.Hour

// magicLinkEmailRLKeyPrefix is the Redis key prefix for per-email rate limits.
// Kept as a named constant so tests and monitoring can grep for it without
// coupling to a string literal buried in a format string.
const magicLinkEmailRLKeyPrefix = "ml:email:rl"

// magicLinkStartMaxBodyBytes caps the inbound POST /auth/email/start JSON
// body. Real bodies are ~80 bytes (email + return_to); 1 KiB is comfortable
// for a future field without inviting megabyte-sized abuse payloads. The
// global Fiber BodyLimit is 50 MiB for /deploy/new tarballs — far too
// generous for a 2-field JSON envelope (B4-F5, BugBash 2026-05-20).
const magicLinkStartMaxBodyBytes = 1024

// MagicLinkHandler implements the passwordless email login flow:
//   POST /auth/email/start    — generates a token, emails the link, returns 202
//   GET  /auth/email/callback — consumes the token, mints a session JWT,
//                               302s back to the dashboard with ?session_token=<jwt>
//
// The mailer field is the magicLinkMailer interface (defined in
// internal_resend_magic_link.go) rather than *email.Client so the circuit-
// breaker wrapper can be slotted in without touching the handler logic.
// *email.Client satisfies the interface directly.
type MagicLinkHandler struct {
	db   *sql.DB
	cfg  *config.Config
	mail magicLinkMailer
	auth *AuthHandler // for IssueSessionJWT + FindOrCreateUserByEmail
	rdb  *redis.Client // for per-email rate limiting (A04); nil → fail-open
}

// NewMagicLinkHandler wires the dependencies. Note that we take an AuthHandler
// rather than reimplementing user/team upsert and JWT signing — the magic-link
// flow lands users in exactly the same spot the GitHub/Google flows do.
//
// Accepts a concrete *email.Client for backwards compatibility with existing
// router + test call sites. Tests that need to inject a stub or the circuit-
// breaker wrapper should use NewMagicLinkHandlerWithMailer.
func NewMagicLinkHandler(db *sql.DB, cfg *config.Config, mail *email.Client, auth *AuthHandler) *MagicLinkHandler {
	return &MagicLinkHandler{db: db, cfg: cfg, mail: mail, auth: auth}
}

// NewMagicLinkHandlerWithMailer is the interface-accepting constructor.
// router.go uses this when wrapping *email.Client with circuitBreakingMailer;
// tests use it to inject a stub. The narrow magicLinkMailer surface
// (SendMagicLink only) keeps the test double tiny.
func NewMagicLinkHandlerWithMailer(db *sql.DB, cfg *config.Config, mail magicLinkMailer, auth *AuthHandler) *MagicLinkHandler {
	return &MagicLinkHandler{db: db, cfg: cfg, mail: mail, auth: auth}
}

// NewMagicLinkHandlerWithMailerAndRedis is the full constructor used by
// router.go. It wires Redis for the per-email rate limit (A04). When rdb
// is nil the handler falls back to NewMagicLinkHandlerWithMailer behaviour
// (no per-email rate limit — fail-open).
func NewMagicLinkHandlerWithMailerAndRedis(db *sql.DB, cfg *config.Config, mail magicLinkMailer, auth *AuthHandler, rdb *redis.Client) *MagicLinkHandler {
	return &MagicLinkHandler{db: db, cfg: cfg, mail: mail, auth: auth, rdb: rdb}
}

// emailRateLimitKey returns the Redis key for a given normalised email address.
// Uses a SHA-256 hash of the email so PII (email addresses) never appear as
// Redis key names in logs, Redis MONITOR output, or memory dumps.
//
// B4-F2 (BugBash 2026-05-20): previously truncated to h[:8] (8 bytes / 64
// bits) which has a birthday-collision space of only ~2^32 attempts. An
// attacker could plausibly grind ~4B email candidates to find two that
// share a fingerprint and use the false-collision to bypass the per-email
// limit on a victim's address. Use the full 32-byte digest — 256-bit
// collision space is the same defence the canonical Redis cache keys
// elsewhere in the codebase use.
func emailRateLimitKey(emailAddr string) string {
	h := sha256.Sum256([]byte(emailAddr))
	return fmt.Sprintf("%s:%x", magicLinkEmailRLKeyPrefix, h[:])
}

// checkEmailRateLimit increments the per-email Redis counter and returns
// (limited, err). If Redis is unavailable the function returns (false, err)
// so the caller fails open (convention 1 in CLAUDE.md). A limited==true
// result means the caller should silently absorb the request (return 202)
// without generating a new magic-link token — the attacker learns nothing
// from the response shape.
func checkEmailRateLimit(ctx context.Context, rdb *redis.Client, emailAddr string) (limited bool, err error) {
	if rdb == nil {
		return false, nil
	}
	key := emailRateLimitKey(emailAddr)
	pipe := rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, magicLinkEmailRateLimitWindow)
	if _, execErr := pipe.Exec(ctx); execErr != nil {
		return false, fmt.Errorf("magic_link.email_rl: %w", execErr)
	}
	count, resultErr := incrCmd.Result()
	if resultErr != nil {
		return false, fmt.Errorf("magic_link.email_rl.result: %w", resultErr)
	}
	return count > int64(magicLinkEmailRateLimit), nil
}

// magicLinkStartRequest is the body for POST /auth/email/start.
type magicLinkStartRequest struct {
	Email    string `json:"email"`
	ReturnTo string `json:"return_to"`
}

// Start handles POST /auth/email/start.
//
// Always returns 202 (or 400 for malformed bodies) regardless of whether the
// email exists in our DB. Revealing existence here would let an attacker
// enumerate users by trying random addresses.
//
// Email send errors are logged but do NOT change the response: the user might
// still get the email seconds later through Resend's retry pipeline, and a
// timing/error-rate side-channel would defeat the enumeration defence above.
//
// A04 (P1): a per-email counter in Redis caps magic-link requests to
// magicLinkEmailRateLimit per magicLinkEmailRateLimitWindow. On Redis error
// the check fails open (CLAUDE.md convention 1) — a Redis outage must never
// block legitimate sign-in attempts. The per-IP global rate limit
// (middleware.RateLimit) still applies and acts as the primary backstop;
// the per-email limit is the second layer that prevents targeted mailbox
// flooding by an attacker with many IPs.
func (h *MagicLinkHandler) Start(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	// B4-F5 (BugBash 2026-05-20): the global Fiber BodyLimit is 50MiB to
	// accommodate /deploy/new tarballs — that's far too generous for a
	// 2-field JSON envelope. A 10MB JSON body on /auth/email/start passed
	// silently before this fix: the parser would chew on megabytes of
	// garbage attached to {"email":"a@b.c"}, holding a goroutine + buffer
	// per request. Cap inbound bodies at 1KiB here (a real magic-link
	// request body is ~80 bytes including the longest plausible email +
	// return_to). Anything larger is malformed or hostile.
	if len(c.Body()) > magicLinkStartMaxBodyBytes {
		return respondError(c, fiber.StatusRequestEntityTooLarge, "payload_too_large",
			"Request body exceeds the 1KiB cap for POST /auth/email/start")
	}

	var body magicLinkStartRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	emailAddr := strings.ToLower(strings.TrimSpace(body.Email))
	if !looksLikeEmail(emailAddr) {
		return respondError(c, fiber.StatusBadRequest, "invalid_email", "A valid email address is required")
	}

	// Per-email rate limit (A04). Fail-open on Redis error so a cache
	// outage never blocks sign-in. The 202 response on the limited path is
	// identical to the success path — the attacker gains no signal.
	limited, rlErr := checkEmailRateLimit(c.Context(), h.rdb, emailAddr)
	if rlErr != nil {
		slog.Warn("magic_link.start.email_rl_error",
			"error", rlErr,
			"request_id", requestID,
		)
		// fail-open: continue as if not limited
	} else if limited {
		// B4-F1 (BugBash 2026-05-20): bump the operator-side metric BEFORE
		// returning 202. The user-visible response stays identical to the
		// success path (no attacker-side enumeration signal), but a
		// monotonically-rising counter surfaces the abuse pattern in NR.
		// Pair with the structured WARN below — the log carries the
		// request_id correlator, the metric carries the rate.
		metrics.MagicLinkEmailRateLimited.Inc()
		slog.Warn("magic_link.start.email_rate_limited",
			"request_id", requestID,
		)
		// Silently absorb — same 202 the non-limited path returns.
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
	}

	returnTo := validateReturnTo(strings.TrimSpace(body.ReturnTo))

	plaintext, err := models.GenerateMagicLinkPlaintext()
	if err != nil {
		slog.Error("magic_link.start.generate_token", "error", err, "request_id", requestID)
		// 202 anyway — never expose backend hiccups in this enumeration-sensitive
		// endpoint.
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
	}

	row, err := models.CreateMagicLink(c.Context(), h.db, emailAddr, plaintext, returnTo, magicLinkTTL)
	if err != nil {
		slog.Error("magic_link.start.db_insert", "error", err, "request_id", requestID)
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
	}

	link := canonicalAPIBase + "/auth/email/callback?t=" + plaintext
	sendErr := h.mail.SendMagicLink(c.Context(), emailAddr, link)
	logMagicLinkSendResult(sendErr, requestID)

	// Persist the send outcome so the worker's magic_link_reconciler can
	// pick up the row and retry on failure. Failure paths here log but
	// never propagate — losing the status write is non-fatal (the
	// reconciler will still see a 'pending' row inside the 15-min TTL
	// window and retry).
	persistMagicLinkSendStatus(c.Context(), h.db, row.ID, sendErr, requestID)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
}

// persistMagicLinkSendStatus writes the send outcome for the row. Failure
// to write the status is logged but not propagated — the user-visible
// behaviour (202) is unchanged, and the worker's reconciler will still
// pick up rows stuck at 'pending' inside the 15-min TTL window.
//
// Exposed (package-private) so the same write path is reachable from the
// /internal/email/resend-magic-link handler the worker calls; the
// reconciler must use exactly the same MarkMagicLink* helpers that the
// Start handler uses, otherwise a model-level invariant could drift.
func persistMagicLinkSendStatus(ctx context.Context, db *sql.DB, id uuid.UUID, sendErr error, requestID string) {
	if sendErr != nil {
		if err := models.MarkMagicLinkSendFailed(ctx, db, id, sendErr); err != nil {
			slog.Error("magic_link.start.persist_failed_status_failed",
				"error", err,
				"link_id", id.String(),
				"request_id", requestID,
			)
		}
		return
	}
	if err := models.MarkMagicLinkSent(ctx, db, id); err != nil {
		slog.Error("magic_link.start.persist_sent_status_failed",
			"error", err,
			"link_id", id.String(),
			"request_id", requestID,
		)
	}
}

// logMagicLinkSendResult logs the success/failure of an email send attempt.
// Exposed (package-private) for unit testing — the false-success-telemetry
// bug of 2026-05-14 (the .sent log fired unconditionally AFTER the warn
// line, hiding the RESEND_API_KEY=CHANGE_ME outage from NR) is exactly
// the class of bug that is only catchable by an assertion against the
// emitted log fields. Keep the two branches mutually exclusive: exactly
// one of {email_send_failed, sent} must fire per call. The .sent line is
// what NR alerts off; do not move it back outside the else branch.
//
// email is intentionally NOT logged at info level to avoid PII spread —
// trace through the magic_links table by created_at if needed.
func logMagicLinkSendResult(sendErr error, requestID string) {
	if sendErr != nil {
		slog.Warn("magic_link.start.email_send_failed",
			"error", sendErr,
			"request_id", requestID,
		)
		return
	}
	slog.Info("magic_link.start.sent",
		"request_id", requestID,
	)
}

// Callback handles GET /auth/email/callback?t=<plaintext>.
//
// Validates the token, atomic-consumes it, finds-or-creates the user/team,
// mints a session JWT, and 302s to <return_to>?session_token=<jwt>.
//
// On any failure path, renders an HTML error page (the user is in a browser).
func (h *MagicLinkHandler) Callback(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	plaintext := strings.TrimSpace(c.Query("t"))
	if plaintext == "" {
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in link is missing its token", "Open the link from your email exactly as we sent it.")
	}

	hash := models.HashMagicLink(plaintext)
	link, err := models.GetMagicLinkForConsumption(c.Context(), h.db, hash)
	if err != nil {
		if errors.Is(err, models.ErrMagicLinkNotFound) {
			return renderAuthError(c, fiber.StatusBadRequest, "Sign-in link is invalid or expired", "Magic links last 15 minutes and can only be used once. Request a new one to continue.")
		}
		slog.Error("magic_link.callback.lookup_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in unavailable", "Please try again in a moment.")
	}

	consumed, err := models.ConsumeMagicLink(c.Context(), h.db, link.ID)
	if err != nil {
		slog.Error("magic_link.callback.consume_failed", "error", err, "request_id", requestID, "link_id", link.ID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in unavailable", "Please try again in a moment.")
	}
	if !consumed {
		// Race: somebody else consumed the row between SELECT and UPDATE. Treat
		// as an already-used link.
		return renderAuthError(c, fiber.StatusBadRequest, "Sign-in link already used", "Request a new sign-in email to continue.")
	}

	user, team, err := h.auth.FindOrCreateUserByEmail(c.Context(), link.Email)
	if err != nil {
		slog.Error("magic_link.callback.user_upsert_failed", "error", err, "request_id", requestID, "link_id", link.ID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not create your account. Please try again.")
	}

	// Completing a magic-link sign-in proves the user controls the inbox the
	// link was delivered to — mark the email verified so it clears the
	// billing/upgrade gate (see handlers/billing.go). Best-effort: a verify
	// flip failure must not break an otherwise-successful login, so a non-nil
	// error is logged and swallowed. user.EmailVerified is updated in memory
	// too so the rest of this request sees the flipped state.
	if !user.EmailVerified {
		if verr := models.SetEmailVerified(c.Context(), h.db, user.ID); verr != nil {
			slog.Error("magic_link.callback.set_email_verified_failed",
				"error", verr, "user_id", user.ID, "request_id", requestID)
		} else {
			user.EmailVerified = true
		}
	}

	sessionToken, err := h.auth.IssueSessionJWT(user, team)
	if err != nil {
		slog.Error("magic_link.callback.jwt_failed", "error", err, "request_id", requestID)
		return renderAuthError(c, fiber.StatusServiceUnavailable, "Sign-in failed", "Could not issue session token.")
	}

	// link.ReturnTo went through validateReturnTo at insert time, but re-check
	// as defence-in-depth in case the allowlist has tightened since.
	returnTo := validateReturnTo(link.ReturnTo)

	slog.Info("magic_link.callback.success",
		"user_id", user.ID, "team_id", team.ID, "request_id", requestID,
	)

	emitAuthLoginAudit(h.db, team.ID, user.ID, user.Email, "email", c.IP(), c.Get("User-Agent"))

	return c.Redirect(appendSessionToken(returnTo, sessionToken), fiber.StatusFound)
}

// looksLikeEmail performs the cheapest plausible check: must contain a single
// '@' with non-empty local-part and a host that contains a '.'. RFC 5321 has
// edge cases (quoted local-parts, IP-literal hosts) we deliberately reject —
// instanode.dev users never have those addresses.
//
// B4-F4 (BugBash 2026-05-20): RFC 5321 §4.5.3.1.1 caps the local-part at
// 64 octets — addresses with a longer local-part are guaranteed-undeliverable
// even when syntactically well-formed. Reject up-front so the magic-link
// pipeline doesn't waste a Brevo send + ledger row on a doomed address.
func looksLikeEmail(s string) bool {
	if len(s) < 3 || len(s) > 254 {
		return false
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	// RFC 5321 §4.5.3.1.1: local-part max 64 octets. `at` is the index of
	// the '@', which is also the byte-length of the local-part (s is ASCII-
	// only here after the upstream trim/lowercase, so byte-length == octet-
	// length for any address that reaches this gate).
	if at > 64 {
		return false
	}
	host := s[at+1:]
	if !strings.Contains(host, ".") {
		return false
	}
	return true
}
