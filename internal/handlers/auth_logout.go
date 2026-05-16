package handlers

// auth_logout.go — server-side session invalidation (A03 tractable fix).
//
// Problem (A03): POST /auth/logout and POST /auth/refresh were advertised in
// the ContractsPage and CLAUDE.md but neither route was registered. logout()
// in src/api/index.ts was entirely client-side (clearToken only). A stolen
// localStorage JWT remained valid for up to 24h after the user clicked
// "Log out" because the server had no revocation mechanism.
//
// Tractable fix implemented here:
//   POST /auth/logout — extracts the JWT's jti claim, stores it in a
//   Redis set ("session.revoked:<jti>") with TTL = token's remaining
//   lifetime. The RequireAuth middleware checks this set on every
//   authenticated request and rejects revoked JTIs with 401.
//
// What this does NOT fix (catalogued per scope decision):
//   - POST /auth/refresh (token rotation) remains unimplemented. The
//     existing 24h single-token model is unchanged. Adding refresh
//     tokens requires a refresh_tokens table, a rotation strategy, and
//     coordinated changes in every SDK and the dashboard's token
//     refresh interceptor — a multi-day effort. The ContractsPage and
//     CLAUDE.md entries for /auth/refresh are corrected in this PR to
//     reflect reality (removed from "LOCKED"; moved to "NEEDS LOCK"
//     with a clear "unimplemented" note).
//   - Active sessions on other devices/tabs are not ejected. The
//     revocation is per-jti (each login produces a distinct jti), so
//     logging out on one device does not invalidate concurrent sessions
//     on other devices. A global "log out everywhere" feature would
//     require a per-team version counter — out of scope.
//   - DPoP-bound tokens: revocation via jti still works for these
//     because RequireAuth's DPoP path also reads the jti after the
//     standard JWT validation. No special casing needed.

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

const (
	// revokedJTIKeyPrefix is the Redis key prefix for revoked JWT IDs.
	// Format: session.revoked:<jti>
	// Kept as a named constant so middleware.IsJTIRevoked (below) can
	// reference it without coupling to a format string literal.
	revokedJTIKeyPrefix = "session.revoked"
)

// RevokedJTIKey returns the Redis key for a given JWT ID.
// Exported so the auth middleware can call it without importing handlers.
// (The middleware package must not import handlers — that would create a cycle.)
// The key format is: session.revoked:<jti>
func RevokedJTIKey(jti string) string {
	return fmt.Sprintf("%s:%s", revokedJTIKeyPrefix, jti)
}

// LogoutHandler handles POST /auth/logout — server-side session invalidation.
type LogoutHandler struct {
	cfg *config.Config
	rdb *redis.Client
}

// NewLogoutHandler constructs a LogoutHandler.
func NewLogoutHandler(cfg *config.Config, rdb *redis.Client) *LogoutHandler {
	return &LogoutHandler{cfg: cfg, rdb: rdb}
}

// Logout handles POST /auth/logout.
//
// The caller must present a valid Bearer token (enforced by RequireAuth at
// the route layer). On success the handler:
//  1. Parses the JWT to extract the jti and exp claims.
//  2. Stores "session.revoked:<jti>" in Redis with TTL = remaining token
//     lifetime (so the key auto-expires when the token would have expired
//     anyway — no Redis bloat from revoked tokens).
//  3. Returns {ok:true}.
//
// On Redis failure the handler logs and returns 503 — a failed revocation
// attempt MUST NOT be silently dropped. The client should retry; clearing
// the local token is always safe but the server-side guarantee requires
// acknowledgement.
//
// Contrast with magic-link rate limiting (fail-open): logout failure is
// not a denial-of-service risk, it is a security gap. Fail-closed is
// the correct posture here.
func (h *LogoutHandler) Logout(c *fiber.Ctx) error {
	requestID := middleware.GetRequestID(c)

	// RequireAuth already validated the token — but we need the raw JWT to
	// extract the jti and exp claims. Re-parse without secret validation is
	// wrong; re-parse with the secret is the correct approach.
	header := c.Get("Authorization")
	if len(header) < 8 || !strings.EqualFold(header[:7], "Bearer ") {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authorization header required")
	}
	tokenStr := header[7:]

	// Re-parse to obtain jti + exp. We re-validate the signature so a
	// race between token expiry and the Parse call can't inject a crafted
	// jti into the revocation set.
	var claims rawLogoutClaims
	parsed, err := jwt.ParseWithClaims(tokenStr, &claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(h.cfg.JWTSecret), nil
	})
	if err != nil || !parsed.Valid {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Token invalid or expired")
	}

	jti := claims.ID
	if jti == "" {
		// Tokens without jti cannot be individually revoked — treat as already
		// expired (these are old dashboard tokens predating the jti field).
		slog.Warn("auth.logout.no_jti",
			"request_id", requestID,
		)
		return c.JSON(fiber.Map{"ok": true})
	}

	// TTL = token remaining lifetime. If exp is in the past (token just
	// expired between RequireAuth and here), store with 1s TTL to flush
	// the key immediately.
	var ttl time.Duration
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			ttl = time.Second
		}
	} else {
		// No exp claim — store for 24h (the maximum session lifetime).
		ttl = 24 * time.Hour
	}

	key := RevokedJTIKey(jti)
	if err := h.rdb.Set(c.Context(), key, "1", ttl).Err(); err != nil {
		slog.Error("auth.logout.revocation_failed",
			"error", err,
			"jti", jti,
			"request_id", requestID,
		)
		// Fail-closed: a failed revocation is a security gap.
		return respondError(c, fiber.StatusServiceUnavailable, "revocation_failed", "Failed to invalidate session — please try again")
	}

	slog.Info("auth.logout.revoked",
		"jti", jti,
		"ttl_s", int(ttl.Seconds()),
		"request_id", requestID,
	)

	return c.JSON(fiber.Map{"ok": true})
}

// rawLogoutClaims is a minimal jwt.Claims implementation that captures the
// jti (ID) and exp claims without the handler package needing to import the
// full sessionClaims shape from auth.go. The two types are structurally
// identical for the fields we need; keeping this separate avoids coupling
// the logout handler to the auth shape.
type rawLogoutClaims struct {
	jwt.RegisteredClaims
}
