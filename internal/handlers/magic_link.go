package handlers

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// magicLinkTTL is how long an emailed sign-in link remains valid.
// 15 minutes is long enough to survive an email-client preview round-trip
// and short enough that a leaked token is rarely useful.
const magicLinkTTL = 15 * time.Minute

// MagicLinkHandler implements the passwordless email login flow:
//   POST /auth/email/start    — generates a token, emails the link, returns 202
//   GET  /auth/email/callback — consumes the token, mints a session JWT,
//                               302s back to the dashboard with ?session_token=<jwt>
type MagicLinkHandler struct {
	db   *sql.DB
	cfg  *config.Config
	mail *email.Client
	auth *AuthHandler // for IssueSessionJWT + FindOrCreateUserByEmail
}

// NewMagicLinkHandler wires the dependencies. Note that we take an AuthHandler
// rather than reimplementing user/team upsert and JWT signing — the magic-link
// flow lands users in exactly the same spot the GitHub/Google flows do.
func NewMagicLinkHandler(db *sql.DB, cfg *config.Config, mail *email.Client, auth *AuthHandler) *MagicLinkHandler {
	return &MagicLinkHandler{db: db, cfg: cfg, mail: mail, auth: auth}
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
func (h *MagicLinkHandler) Start(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	var body magicLinkStartRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}

	emailAddr := strings.ToLower(strings.TrimSpace(body.Email))
	if !looksLikeEmail(emailAddr) {
		return respondError(c, fiber.StatusBadRequest, "invalid_email", "A valid email address is required")
	}

	returnTo := validateReturnTo(strings.TrimSpace(body.ReturnTo))

	plaintext, err := models.GenerateMagicLinkPlaintext()
	if err != nil {
		slog.Error("magic_link.start.generate_token", "error", err, "request_id", requestID)
		// 202 anyway — never expose backend hiccups in this enumeration-sensitive
		// endpoint.
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
	}

	if _, err := models.CreateMagicLink(c.Context(), h.db, emailAddr, plaintext, returnTo, magicLinkTTL); err != nil {
		slog.Error("magic_link.start.db_insert", "error", err, "request_id", requestID)
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
	}

	link := canonicalAPIBase + "/auth/email/callback?t=" + plaintext
	sendErr := h.mail.SendMagicLink(c.Context(), emailAddr, link)
	logMagicLinkSendResult(sendErr, requestID)

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"ok": true})
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
	host := s[at+1:]
	if !strings.Contains(host, ".") {
		return false
	}
	return true
}
