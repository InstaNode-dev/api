package middleware

// revocation.go — JWT JTI revocation check for server-side logout (A03).
//
// The handlers.LogoutHandler writes "session.revoked:<jti>" to Redis when a
// user explicitly logs out. RequireAuth calls IsJTIRevoked to reject sessions
// whose JTI appears in the revocation set.
//
// The middleware package does not import the handlers package (that would
// create a cycle). The key format is duplicated here as revokedJTIKeyPrefix,
// intentionally kept in sync with handlers.revokedJTIKeyPrefix via the
// constant name and the shared format string. If the format ever changes,
// both sites must be updated together — the revocation_sync_test.go file
// enforces this with a golden-string assertion.
//
// Fail-open policy (CLAUDE.md convention 1): a Redis error in IsJTIRevoked
// returns (false, err) so a cache outage never blocks legitimate requests.
// The risk: a revoked token could slip through during a Redis outage. This
// is acceptable given that sessions expire after 24h maximum and the
// alternative (fail-closed) would lock every active user out during
// an outage.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

const (
	// revokedJTIKeyPrefix is the Redis key prefix for revoked JWT IDs.
	// MUST match handlers.revokedJTIKeyPrefix — any drift breaks logout.
	// Format: session.revoked:<jti>
	revokedJTIKeyPrefix = "session.revoked"
)

// revokedJTIKey returns the Redis key for a given JWT ID.
// Mirrors handlers.RevokedJTIKey — the two functions produce identical output.
func revokedJTIKey(jti string) string {
	return fmt.Sprintf("%s:%s", revokedJTIKeyPrefix, jti)
}

// revocationRDB is the module-level Redis client for JTI revocation checks.
// Set via SetRevocationDB called from router.go after the Redis client is
// constructed. Nil → no revocation checks (safe for tests that do not exercise
// logout).
var revocationRDB *redis.Client

// SetRevocationDB wires the Redis client used by IsJTIRevoked.
// Called once from router.go; safe for concurrent reads after the router
// starts (the value is never overwritten after startup).
func SetRevocationDB(rdb *redis.Client) {
	revocationRDB = rdb
}

// IsJTIRevoked reports whether the given JTI appears in the Redis revocation
// set. Returns (false, nil) when the JTI is not revoked or when Redis is
// unavailable (fail-open per CLAUDE.md convention 1).
func IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	if revocationRDB == nil || jti == "" {
		return false, nil
	}
	key := revokedJTIKey(jti)
	val, err := revocationRDB.Exists(ctx, key).Result()
	if err != nil {
		slog.Warn("middleware.revocation.redis_error",
			"error", err,
			"key", key,
		)
		return false, fmt.Errorf("revocation check: %w", err)
	}
	return val > 0, nil
}
