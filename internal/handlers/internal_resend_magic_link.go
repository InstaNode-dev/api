package handlers

// internal_resend_magic_link.go — POST /internal/email/resend-magic-link.
//
// Called by the worker's magic_link_reconciler periodic job (every 60s)
// for any magic_links row stuck at email_send_status IN ('pending',
// 'send_failed') inside the 15-minute TTL window. Body is just the row id;
// the handler looks the row up, re-sends the email via the existing
// circuit-breaker-wrapped mailer, and writes the resulting status back
// to magic_links via MarkMagicLinkSent / MarkMagicLinkSendFailed.
//
// Auth: same shared-secret HS256 JWT pattern as /internal/teams/:id/terminate
// (purpose claim "resend_magic_link", signed with WORKER_INTERNAL_JWT_SECRET).
// Reusing the same secret keeps operator surface small — both internal
// endpoints flip on/off together. The 60s iat freshness gate prevents a
// captured worker token from being replayed indefinitely.
//
// Three-attempt cap is enforced HERE (not in the model layer) so the
// abandonment policy lives in one place: this handler. After the 3rd
// failed attempt the row is flipped to email_send_status='send_abandoned'
// and an operator-visible WARN line fires
// (magic_link.resend.send_abandoned) so NR alerting can pick it up.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// internalResendMagicLinkPurpose is the required `purpose` claim on the
// worker-minted JWT for this route. Distinct from internalTerminatePurpose
// so a captured terminate token can't be replayed to drive resends, and
// vice-versa.
const internalResendMagicLinkPurpose = "resend_magic_link"

// magicLinkResendAttemptCap is the hard ceiling on send attempts. The
// reconcile query in ListMagicLinksForReconcile already filters
// email_send_attempts < 3, but we re-check here to defend against a
// concurrent reconciler tick that read a row at 2 attempts and races to
// drive the 3rd.
const magicLinkResendAttemptCap = 3

// InternalResendMagicLinkHandler wires the dependencies for the resend
// route. Constructed once in router.go; the handler closure captures it.
//
// The mailer is the same magicLinkMailer interface the Start handler uses,
// so the circuit-breaker wrap covers both call sites — if Resend / Brevo
// is degraded the breaker opens for resends just as it does for new sends.
type InternalResendMagicLinkHandler struct {
	db   *sql.DB
	cfg  *config.Config
	mail magicLinkMailer
}

// NewInternalResendMagicLinkHandler constructs the handler.
func NewInternalResendMagicLinkHandler(db *sql.DB, cfg *config.Config, mail magicLinkMailer) *InternalResendMagicLinkHandler {
	return &InternalResendMagicLinkHandler{db: db, cfg: cfg, mail: mail}
}

// magicLinkMailer is the narrow surface the magic-link handlers use to
// send email. *email.Client satisfies it directly today; the circuit-
// breaker wrapper in magic_link_circuit.go also satisfies it so a single
// constructor swap in router.go puts the breaker in front of the mailer
// without touching the handler signatures.
type magicLinkMailer interface {
	SendMagicLink(ctx context.Context, toEmail, link string) error
}

// internalResendMagicLinkClaims is the worker-minted JWT shape. Mirrors
// the structure used by internal_terminate.go.
type internalResendMagicLinkClaims struct {
	Purpose string `json:"purpose"`
	LinkID  string `json:"link_id"`
	jwt.RegisteredClaims
}

// internalResendMagicLinkRequest is the body the worker posts. The link_id
// is the magic_links row UUID we should resend.
type internalResendMagicLinkRequest struct {
	LinkID string `json:"link_id"`
}

// Resend is the fiber.Handler for POST /internal/email/resend-magic-link.
//
// API-27/78 (QA 2026-05-29): the auth check runs FIRST — before any body
// parsing — so a bogus token paired with a malformed body returns 401
// internal_token_required (the actual fault) instead of 400 invalid_body.
// The pre-fix order let an unauthenticated probe distinguish "no body"
// (400) from "no auth" (401), inverting the fail-closed posture documented
// for the /internal/* routes.
func (h *InternalResendMagicLinkHandler) Resend(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	// Auth-first. The secret-unset branch must fire before we even look
	// at the body so a probe can't tell "operator hasn't deployed the
	// secret" from "operator deployed the secret but caller has wrong
	// token" by the 401/400 envelope shape.
	if h.cfg == nil || strings.TrimSpace(h.cfg.WorkerInternalJWTSecret) == "" {
		slog.Warn("internal.resend_magic_link.secret_unset",
			"request_id", requestID,
			"reason", "WORKER_INTERNAL_JWT_SECRET is empty; rejecting all calls",
		)
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal auth is not configured on this api Deployment.")
	}
	if err := preVerifyInternalResendMagicLinkJWT(c, h.cfg.WorkerInternalJWTSecret); err != nil {
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal token is missing or invalid.")
	}

	// Auth-accepted. Parse the body. A malformed body from an authenticated
	// caller is genuinely a 400 (worker emitted a bad payload).
	var body internalResendMagicLinkRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Request body must be valid JSON")
	}
	linkID, err := uuid.Parse(strings.TrimSpace(body.LinkID))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_link_id", "link_id must be a UUID")
	}

	// Second-phase verify: bind the token's link_id claim to the body's
	// link_id. Cross-link replay defence.
	if err := verifyInternalResendMagicLinkJWT(c, h.cfg.WorkerInternalJWTSecret, linkID); err != nil {
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal token is missing or invalid.")
	}

	ctx := c.Context()
	row, err := models.GetMagicLinkByID(ctx, h.db, linkID)
	if err != nil {
		if errors.Is(err, models.ErrMagicLinkNotFound) {
			return respondError(c, fiber.StatusNotFound, "magic_link_not_found", "no magic_links row with that id")
		}
		slog.Error("internal.resend_magic_link.lookup_failed",
			"error", err,
			"link_id", linkID.String(),
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to load magic link")
	}

	// TTL gate. The consumer path (GET /auth/email/callback) rejects
	// expired rows anyway; resending a doomed-to-fail link wastes a send
	// quota and confuses the user.
	if time.Now().UTC().After(row.ExpiresAt) {
		slog.Info("internal.resend_magic_link.expired_skip",
			"link_id", linkID.String(),
			"request_id", requestID,
			"expired_at", row.ExpiresAt.Format(time.RFC3339),
		)
		return c.JSON(fiber.Map{
			"ok":     true,
			"status": "expired",
		})
	}

	// We deliberately re-send to the SAME email address and use the SAME
	// token hash as the original row — the user's email-client preview
	// scanner may have already burned one delivery attempt, but the
	// plaintext token they got is the one we need to keep working. We
	// don't store plaintext, so we have to derive a fresh callback URL
	// using the stored hash's only public projection: the row id.
	//
	// IMPORTANT LIMITATION: this handler resends a NEW plaintext token
	// because the original plaintext was discarded after hashing. The
	// receiver gets a fresh link; the original first-attempt link (if
	// any) is invalidated by GetMagicLinkForConsumption finding no row
	// with that hash. Acceptable for a resend flow — the user was
	// going to lose the original email's link anyway since they never
	// got it.
	plaintext, err := models.GenerateMagicLinkPlaintext()
	if err != nil {
		slog.Error("internal.resend_magic_link.generate_token_failed",
			"error", err,
			"link_id", linkID.String(),
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "token_failed", "failed to mint resend token")
	}
	newHash := models.HashMagicLink(plaintext)
	if err := models.UpdateMagicLinkTokenHash(ctx, h.db, linkID, newHash); err != nil {
		slog.Error("internal.resend_magic_link.update_hash_failed",
			"error", err,
			"link_id", linkID.String(),
			"request_id", requestID,
		)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "failed to rotate token")
	}

	link := canonicalAPIBase + "/auth/email/callback?t=" + plaintext
	sendErr := h.mail.SendMagicLink(ctx, row.Email, link)

	// Three-attempt cap. row.email_send_attempts was loaded BEFORE this
	// send; after the model marks the result the count goes up by 1.
	// If the resulting count would be >= magicLinkResendAttemptCap AND
	// the send failed, abandon.
	if sendErr != nil {
		// Look up the FRESH attempt count to defend against a concurrent
		// reconciler tick that already incremented it. The Mark*Failed
		// helper increments unconditionally; we re-read the row to see
		// where it landed.
		if err := models.MarkMagicLinkSendFailed(ctx, h.db, linkID, sendErr); err != nil {
			slog.Error("internal.resend_magic_link.mark_failed_failed",
				"error", err,
				"link_id", linkID.String(),
				"request_id", requestID,
			)
		}
		freshAttempts, lookupErr := readMagicLinkAttempts(ctx, h.db, linkID)
		if lookupErr != nil {
			slog.Warn("internal.resend_magic_link.attempts_lookup_failed",
				"error", lookupErr,
				"link_id", linkID.String(),
				"request_id", requestID,
			)
		}
		if freshAttempts >= magicLinkResendAttemptCap {
			if err := models.MarkMagicLinkSendAbandoned(ctx, h.db, linkID); err != nil {
				slog.Error("internal.resend_magic_link.mark_abandoned_failed",
					"error", err,
					"link_id", linkID.String(),
					"request_id", requestID,
				)
			}
			// Operator-visible: NR should alert when this fires. A
			// magic-link the user requested has been permanently
			// abandoned after 3 send attempts — likely a provider
			// outage or a bad address.
			slog.Warn("magic_link.resend.send_abandoned",
				"link_id", linkID.String(),
				"request_id", requestID,
				"attempts", freshAttempts,
				"last_error", sendErr.Error(),
			)
			return c.JSON(fiber.Map{
				"ok":       true,
				"status":   "abandoned",
				"attempts": freshAttempts,
			})
		}
		slog.Warn("magic_link.resend.send_failed",
			"link_id", linkID.String(),
			"request_id", requestID,
			"attempts", freshAttempts,
			"error", sendErr.Error(),
		)
		return c.JSON(fiber.Map{
			"ok":       true,
			"status":   "send_failed",
			"attempts": freshAttempts,
		})
	}

	if err := models.MarkMagicLinkSent(ctx, h.db, linkID); err != nil {
		slog.Error("internal.resend_magic_link.mark_sent_failed",
			"error", err,
			"link_id", linkID.String(),
			"request_id", requestID,
		)
	}
	slog.Info("magic_link.resend.sent",
		"link_id", linkID.String(),
		"request_id", requestID,
	)
	return c.JSON(fiber.Map{
		"ok":     true,
		"status": "sent",
	})
}

// readMagicLinkAttempts is a small projection that pulls the fresh
// email_send_attempts value after a Mark*Failed increment. Kept here (not
// in models/) because it's a defensive read tied to the cap-enforcement
// path; the model API surface should not advertise this internal-only
// projection.
func readMagicLinkAttempts(ctx context.Context, db *sql.DB, id uuid.UUID) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT email_send_attempts FROM magic_links WHERE id = $1`, id).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// preVerifyInternalResendMagicLinkJWT is the auth-first gate that runs
// BEFORE body parsing. Mirrors preVerifyInternalTerminateJWT — every JWT
// structural check that does NOT depend on body fields runs here; the
// link_id-claim-binds-to-body check is deferred to
// verifyInternalResendMagicLinkJWT after the body parses cleanly.
// API-27/78 (QA 2026-05-29).
func preVerifyInternalResendMagicLinkJWT(c *fiber.Ctx, secret string) error {
	authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		slog.Warn("internal.resend_magic_link.preauth.missing_bearer")
		return errors.New("missing bearer token")
	}
	tokenStr := strings.TrimSpace(authHeader[len("Bearer "):])
	claims := &internalResendMagicLinkClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		slog.Warn("internal.resend_magic_link.preauth.parse_failed", "error", err)
		return err
	}
	if claims.Purpose != internalResendMagicLinkPurpose {
		slog.Warn("internal.resend_magic_link.preauth.bad_purpose",
			"got", claims.Purpose,
			"want", internalResendMagicLinkPurpose,
		)
		return errors.New("wrong purpose claim")
	}
	if claims.IssuedAt == nil {
		slog.Warn("internal.resend_magic_link.preauth.missing_iat")
		return errors.New("missing iat claim")
	}
	skew := time.Since(claims.IssuedAt.Time)
	if skew < -60*time.Second || skew > 60*time.Second {
		slog.Warn("internal.resend_magic_link.preauth.iat_skew", "skew_seconds", skew.Seconds())
		return errors.New("iat outside skew window")
	}
	return nil
}

// verifyInternalResendMagicLinkJWT parses + validates the bearer token
// against the four required checks:
//
//  1. HS256 signed with cfg.WorkerInternalJWTSecret.
//  2. `purpose` claim equals "resend_magic_link".
//  3. `iat` claim is within ±60s of now.
//  4. `link_id` claim equals the body's link_id (binds the token to a
//     specific row so a captured token can't drive resends on other rows).
func verifyInternalResendMagicLinkJWT(c *fiber.Ctx, secret string, linkID uuid.UUID) error {
	authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		slog.Warn("internal.resend_magic_link.auth.missing_bearer", "link_id", linkID.String())
		return errors.New("missing bearer token")
	}
	tokenStr := strings.TrimSpace(authHeader[len("Bearer "):])
	if tokenStr == "" {
		slog.Warn("internal.resend_magic_link.auth.empty_token", "link_id", linkID.String())
		return errors.New("empty bearer token")
	}

	claims := &internalResendMagicLinkClaims{}
	// T10 P2-1 (BugHunt 2026-05-20): pin HS256 only via WithValidMethods.
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		slog.Warn("internal.resend_magic_link.auth.parse_failed", "error", err, "link_id", linkID.String())
		return err
	}
	if !tok.Valid {
		slog.Warn("internal.resend_magic_link.auth.token_invalid", "link_id", linkID.String())
		return errors.New("token marked invalid")
	}
	if claims.Purpose != internalResendMagicLinkPurpose {
		slog.Warn("internal.resend_magic_link.auth.bad_purpose",
			"got", claims.Purpose,
			"want", internalResendMagicLinkPurpose,
			"link_id", linkID.String(),
		)
		return errors.New("wrong purpose claim")
	}
	if claims.LinkID != linkID.String() {
		slog.Warn("internal.resend_magic_link.auth.link_id_mismatch",
			"jwt_link_id", claims.LinkID,
			"path_link_id", linkID.String(),
		)
		return errors.New("link_id mismatch")
	}
	if claims.IssuedAt == nil {
		slog.Warn("internal.resend_magic_link.auth.missing_iat", "link_id", linkID.String())
		return errors.New("missing iat claim")
	}
	skew := time.Since(claims.IssuedAt.Time)
	if skew < -60*time.Second || skew > 60*time.Second {
		slog.Warn("internal.resend_magic_link.auth.iat_skew",
			"skew_seconds", skew.Seconds(),
			"link_id", linkID.String(),
		)
		return errors.New("iat outside skew window")
	}
	return nil
}

