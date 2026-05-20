package middleware

// presign_token_rate_limit.go — per-token sliding-window rate limit for
// POST /storage/:token/presign (B17-P0).
//
// The route's auth is the token in the URL (a UUID-shaped bearer). The
// global per-IP RateLimit (app.Use scope) already caps abuse from a single
// network fingerprint, but a leaked token used from a botnet of distinct
// IPs would slip past it. This middleware adds a SECOND counter, keyed on
// the token itself, so a single leaked token cannot mint more than
// PresignPerTokenPerMinute presigned URLs per rolling minute regardless
// of the source IP distribution.
//
// Algorithm: Redis ZSET sliding window, same shape as admin_rate_limit.go.
// Excess returns 429 with the canonical envelope (Retry-After header +
// retry_after_seconds in the JSON body) — this differs from
// AdminRateLimit's masked-403 because there is nothing to hide on a public
// /storage/:token endpoint (the token IS the identity).
//
// Order in the presign chain (see internal/router/router.go):
//
//   RateLimit (global per-IP, app.Use) → BodyLimit → OptionalAuth →
//     PresignTokenRateLimit (this) → Idempotency → handler
//
// PresignTokenRateLimit runs after OptionalAuth so the audit log captured
// inside the handler has team_id populated when a session is present, but
// BEFORE the handler so the rejected request never hits the resource
// lookup or signing path.
//
// Fail-open on Redis errors: matches every other rate limiter in this
// codebase (CLAUDE.md convention 1). A Redis outage must not break a
// legitimate broker-mode read/write loop.

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/metrics"
)

const (
	// PresignPerTokenPerMinute is the per-token cap on /storage/:token/presign
	// hits within a rolling 60-second window. Sized for legitimate agent
	// usage: a typical broker-mode read loop calls presign once per object
	// access; 10/min covers occasional dashboard previews and small batches
	// without enabling a leaked token to be used as an unbounded signing
	// oracle. Hobby+/Pro tiers should issue an SDK-token / Worker instead
	// of calling presign at high cadence.
	PresignPerTokenPerMinute = 10

	// presignRateLimitKeyPrefix is the Redis key namespace.
	presignRateLimitKeyPrefix = "rl_presign"

	// presignRateLimitTTL is the lifetime on the Redis ZSET. Just over an
	// hour is enough for the sliding window to drain between bursts and
	// for ZREMRANGEBYSCORE to keep memory bounded.
	presignRateLimitTTL = 25 * time.Hour

	// presignRateLimitWindow is the rolling window size (the "10 req per
	// MINUTE" denominator).
	presignRateLimitWindow = 60 * time.Second
)

// PresignTokenRateLimit returns a Fiber middleware enforcing
// PresignPerTokenPerMinute hits per :token URL param per rolling minute.
// On excess it returns 429 with the canonical ErrorResponse envelope
// (Retry-After + retry_after_seconds). On Redis error it logs and falls
// through (fail-open — convention 1).
//
// rdb may be nil — in that case the middleware degrades to a no-op
// pass-through. The router doesn't wire a nil Redis in production; the
// nil tolerance is for tests that build a partial Fiber app without Redis.
func PresignTokenRateLimit(rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if rdb == nil {
			return c.Next()
		}
		token := c.Params("token")
		if token == "" {
			// Router should always populate :token — but if it didn't, the
			// handler's own UUID parse will reject the request. Pass
			// through so the parse-error path stays singular.
			return c.Next()
		}

		over, err := presignRateLimitExceeded(c.Context(), rdb, token)
		if err != nil {
			slog.Error("presign_rate_limit.redis_error",
				"error", err,
				"token_prefix", maskPresignToken(token),
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("presign_rate_limit").Inc()
			metrics.FailOpenEvents.WithLabelValues("presign_token_rate_limit", "redis_unavailable").Inc()
			return c.Next()
		}
		if over {
			metrics.FingerprintAbuseBlocked.Inc()
			retryAfter := int(presignRateLimitWindow.Seconds())
			c.Set(fiber.HeaderRetryAfter, strconv.Itoa(retryAfter))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"ok":                  false,
				"error":               "rate_limited",
				"message":             "too many presign requests for this token; slow down",
				"request_id":          GetRequestID(c),
				"retry_after_seconds": retryAfter,
				"agent_action":        "Wait at least 60 seconds before requesting another presigned URL for this token, or batch your reads into a single signed URL.",
			})
		}
		return c.Next()
	}
}

// presignRateLimitExceeded implements the per-token sliding-window check
// against Redis. Same algorithm as adminRateLimitExceeded (see
// admin_rate_limit.go for the full rationale).
func presignRateLimitExceeded(ctx context.Context, rdb *redis.Client, token string) (bool, error) {
	key := fmt.Sprintf("%s:%s", presignRateLimitKeyPrefix, token)
	now := time.Now()
	cutoff := now.Add(-presignRateLimitWindow).UnixNano()
	score := now.UnixNano()
	// member must be unique per call — score alone collides under load.
	member := fmt.Sprintf("%d:%d", score, score%1000003)

	pipe := rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("(%d", cutoff))
	cardCmd := pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(score), Member: member})
	pipe.Expire(ctx, key, presignRateLimitTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("presign_rate_limit pipeline: %w", err)
	}
	count, err := cardCmd.Result()
	if err != nil {
		return false, fmt.Errorf("presign_rate_limit zcard: %w", err)
	}
	// count is the size of the ZSET AFTER cleanup, BEFORE this request's
	// ZADD has been observed (Redis pipelines preserve order but the
	// in-flight ZCARD reads the state at its execution point). count >= cap
	// means "the last `cap` calls fall inside the window, this one would
	// be the (cap+1)th."
	return count >= int64(PresignPerTokenPerMinute), nil
}

// maskPresignToken returns the first 8 chars of a token for logging,
// avoiding leaking the full bearer secret into slog output / NR Log.
// Matches the pattern used elsewhere in this codebase (worker
// quota_infra.go) for resource bearer tokens.
func maskPresignToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}
