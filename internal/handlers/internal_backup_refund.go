package handlers

// internal_backup_refund.go — POST /internal/teams/:id/backup-quota/refund.
//
// Called by the worker's customer_backup_runner when a MANUAL backup row
// fails terminally (pg_dump errored, S3 upload errored, integrity check
// failed). Pre-fix (#65/#Q47 B36) a failed manual backup still burned the
// team's daily manual-backups counter — so a hobby team that hit a
// flaky pg_dump lost their one-per-day allowance to a failure they did
// not cause. This endpoint decrements the per-team UTC-day counter in
// Redis so the next legitimate retry sees the same headroom.
//
// Auth: same WORKER_INTERNAL_JWT_SECRET HS256 shape as
// /internal/teams/:id/terminate — the worker mints a short-lived JWT
// (purpose=internal_backup_refund) and the api verifies it here.
//
// Idempotency: the request body carries a backup_id and we Redis-SETNX
// a "refunded:<backup_id>" marker for 36h. Subsequent calls for the same
// backup_id are no-ops (return 200 with refunded=false). The counter
// itself is decremented only on the first successful refund.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/config"
)

const (
	internalBackupRefundPurpose      = "internal_backup_refund"
	internalBackupRefundMaxClockSkew = 60 * time.Second
)

// InternalBackupRefundHandler wires the dependencies for the refund
// endpoint. Constructed once in router.go.
type InternalBackupRefundHandler struct {
	db  *sql.DB
	rdb *redis.Client
	cfg *config.Config
	now func() time.Time
}

// NewInternalBackupRefundHandler constructs the handler. now defaults to
// time.Now; tests pin a deterministic clock.
func NewInternalBackupRefundHandler(db *sql.DB, rdb *redis.Client, cfg *config.Config) *InternalBackupRefundHandler {
	return &InternalBackupRefundHandler{db: db, rdb: rdb, cfg: cfg, now: time.Now}
}

type internalBackupRefundClaims struct {
	Purpose string `json:"purpose"`
	TeamID  string `json:"team_id"`
	jwt.RegisteredClaims
}

// Refund is the fiber.Handler for POST /internal/teams/:id/backup-quota/refund.
//
// Request body:
//
//	{"backup_id": "<uuid>"}
//
// Response on success:
//
//	{"ok": true, "refunded": true|false, "backup_id": "<uuid>"}
//
// refunded=false means a prior call already credited the counter for
// this backup_id (idempotent no-op).
func (h *InternalBackupRefundHandler) Refund(c *fiber.Ctx) error {
	// API-28 (QA 2026-05-29): auth-first. Mirror the terminate + resend
	// handlers — the secret-unset / preauth gate runs BEFORE the path :id
	// parse so an unauth POST with a junk path returns 401
	// internal_token_required (the actual fault) instead of 400
	// invalid_team_id. Pre-fix order let a probe distinguish "path bad"
	// from "auth bad" by the envelope code — fail-closed inversion.
	if h.cfg == nil || strings.TrimSpace(h.cfg.WorkerInternalJWTSecret) == "" {
		slog.Warn("internal.backup_refund.secret_unset",
			"reason", "WORKER_INTERNAL_JWT_SECRET is empty; rejecting all calls",
		)
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal auth is not configured on this api Deployment.")
	}
	if err := preVerifyInternalBackupRefundJWT(c, h.cfg.WorkerInternalJWTSecret); err != nil {
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal token is missing or invalid.")
	}

	// Auth-accepted — now parse path :id. Malformed :id from authenticated
	// caller is 400 (worker emitted a bad URL).
	pathID := strings.TrimSpace(c.Params("id"))
	teamID, err := uuid.Parse(pathID)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	// Second-phase verify: bind the token's team_id claim to the path.
	if err := verifyInternalBackupRefundJWT(c, h.cfg.WorkerInternalJWTSecret, teamID); err != nil {
		return respondError(c, fiber.StatusUnauthorized, "internal_token_required",
			"Worker internal token is missing or invalid.")
	}

	var body struct {
		BackupID string `json:"backup_id"`
	}
	rawBody := c.Body()
	if len(rawBody) > 0 {
		if err := json.Unmarshal(rawBody, &body); err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_body", "Body must be valid JSON")
		}
	}
	backupIDStr := strings.TrimSpace(body.BackupID)
	if backupIDStr == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_backup_id", "backup_id is required")
	}
	if _, err := uuid.Parse(backupIDStr); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_backup_id", "backup_id must be a UUID")
	}

	// Redis is the source of truth for the daily counter. Same key shape
	// as CreateBackup: manual_backup:<team>:<YYYY-MM-DD>.
	ctx := c.UserContext()
	utc := h.now().UTC().Format("2006-01-02")
	counterKey := fmt.Sprintf("manual_backup:%s:%s", teamID.String(), utc)
	markerKey := fmt.Sprintf("manual_backup_refunded:%s:%s", teamID.String(), backupIDStr)

	if h.rdb == nil {
		// Redis disabled — fail-open. Returning 200 lets the worker keep
		// the row marked failed without retry-storming this endpoint.
		slog.Warn("internal.backup_refund.redis_disabled",
			"team_id", teamID, "backup_id", backupIDStr)
		return c.JSON(fiber.Map{
			"ok":        true,
			"refunded":  false,
			"backup_id": backupIDStr,
			"reason":    "redis_disabled",
		})
	}

	// SETNX the per-backup marker. Returns true if we won the race
	// (first refund); false if a prior call already credited.
	winner, setErr := h.rdb.SetNX(ctx, markerKey, "1", 36*time.Hour).Result()
	if setErr != nil {
		slog.Warn("internal.backup_refund.marker_setnx_failed",
			"team_id", teamID, "backup_id", backupIDStr, "error", setErr)
		// Fail open — better to skip the refund than to retry-storm.
		return c.JSON(fiber.Map{
			"ok":        true,
			"refunded":  false,
			"backup_id": backupIDStr,
			"reason":    "redis_setnx_failed",
		})
	}
	if !winner {
		return c.JSON(fiber.Map{
			"ok":        true,
			"refunded":  false,
			"backup_id": backupIDStr,
			"reason":    "already_refunded",
		})
	}

	// Decrement the counter. We only do this when winner=true, so the
	// counter can't underflow on retries. A counter that doesn't exist
	// (worker pod restarted at midnight UTC) will DECR to -1 — that's
	// fine because the CreateBackup INCR path only blocks above the
	// per-day cap; -1 just adds 1 unit of headroom to the next day's
	// counter, which is the desired behavior.
	if _, decErr := h.rdb.Decr(ctx, counterKey).Result(); decErr != nil {
		slog.Warn("internal.backup_refund.decr_failed",
			"team_id", teamID, "backup_id", backupIDStr, "error", decErr)
		// We already set the marker — un-setting it on a DECR failure
		// would race with concurrent successful refunds. Log and move on;
		// the customer just loses 1 unit of headroom (same as pre-fix).
	}

	slog.Info("internal.backup_refund.credited",
		"team_id", teamID,
		"backup_id", backupIDStr,
		"counter_key", counterKey,
	)
	return c.JSON(fiber.Map{
		"ok":        true,
		"refunded":  true,
		"backup_id": backupIDStr,
	})
}

// preVerifyInternalBackupRefundJWT is the auth-first gate that runs BEFORE
// the path :id parse. Mirrors preVerifyInternalTerminateJWT — every JWT
// structural check that does NOT depend on the path :id runs here; the
// team_id-claim-binds-to-path check is deferred to
// verifyInternalBackupRefundJWT after the path parses cleanly.
// API-28 (QA 2026-05-29).
func preVerifyInternalBackupRefundJWT(c *fiber.Ctx, secret string) error {
	authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		slog.Warn("internal.backup_refund.preauth.missing_bearer")
		return errors.New("missing bearer token")
	}
	tokenStr := strings.TrimSpace(authHeader[len("Bearer "):])
	claims := &internalBackupRefundClaims{}
	// WithValidMethods([HS256]) pins alg; non-HS256 short-circuits.
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(_ *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		slog.Warn("internal.backup_refund.preauth.parse_failed", "error", err)
		return err
	}
	if claims.Purpose != internalBackupRefundPurpose {
		slog.Warn("internal.backup_refund.preauth.bad_purpose", "purpose", claims.Purpose)
		return errors.New("purpose claim mismatch")
	}
	if claims.IssuedAt == nil {
		return errors.New("missing iat claim")
	}
	now := time.Now()
	if claims.IssuedAt.Before(now.Add(-internalBackupRefundMaxClockSkew)) ||
		claims.IssuedAt.After(now.Add(internalBackupRefundMaxClockSkew)) {
		return errors.New("iat outside clock skew window")
	}
	return nil
}

func verifyInternalBackupRefundJWT(c *fiber.Ctx, secret string, pathTeamID uuid.UUID) error {
	authHeader := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		slog.Warn("internal.backup_refund.auth.missing_bearer", "path_team_id", pathTeamID.String())
		return errors.New("missing bearer token")
	}
	tokenStr := strings.TrimSpace(authHeader[len("Bearer "):])
	if tokenStr == "" {
		return errors.New("empty bearer token")
	}
	claims := &internalBackupRefundClaims{}
	// T10 P2-1 (BugHunt 2026-05-20): pin alg to HS256 only — see comment
	// in middleware/auth.go. Internal M2M JWTs share the codebase's alg
	// posture; downgrade to HS384/HS512 must be uniformly forbidden.
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		slog.Warn("internal.backup_refund.auth.parse_failed",
			"error", err, "path_team_id", pathTeamID.String())
		return err
	}
	if !tok.Valid {
		return errors.New("token marked invalid")
	}
	if claims.Purpose != internalBackupRefundPurpose {
		slog.Warn("internal.backup_refund.auth.bad_purpose",
			"purpose", claims.Purpose, "path_team_id", pathTeamID.String())
		return errors.New("purpose claim mismatch")
	}
	if claims.IssuedAt == nil {
		return errors.New("missing iat claim")
	}
	now := time.Now()
	if claims.IssuedAt.Before(now.Add(-internalBackupRefundMaxClockSkew)) ||
		claims.IssuedAt.After(now.Add(internalBackupRefundMaxClockSkew)) {
		return errors.New("iat outside clock skew window")
	}
	claimTeamID, err := uuid.Parse(strings.TrimSpace(claims.TeamID))
	if err != nil {
		return errors.New("team_id claim not a UUID")
	}
	if claimTeamID != pathTeamID {
		slog.Warn("internal.backup_refund.auth.team_mismatch",
			"team_id_claim", claimTeamID.String(),
			"path_team_id", pathTeamID.String())
		return errors.New("team_id claim/path mismatch")
	}
	return nil
}
