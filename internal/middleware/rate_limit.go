package middleware

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
	// LocalKeyRateLimitExceeded is the Fiber locals key set when the rate limit is exceeded.
	LocalKeyRateLimitExceeded = "rate_limit_exceeded"
	// LocalKeyRateLimitCount is the Fiber locals key holding the current counter value.
	LocalKeyRateLimitCount = "rate_limit_count"
	// LocalKeyRateLimitKey is the Fiber locals key holding the per-day Redis
	// counter key (shape: "<prefix>:<fingerprint>:<YYYY-MM-DD>"). Stashed by
	// the RateLimit middleware so downstream code (notably the idempotency
	// cache-hit path) can DECR the exact key that was just INCR'd without
	// re-deriving the prefix or the date format. Empty when no fingerprint
	// is available or when RateLimit failed open.
	LocalKeyRateLimitKey = "rate_limit_key"
	// LocalKeyRateLimitConfiguredLimit is the Fiber locals key holding the
	// configured limit (cfg.Limit). Stashed so RefundRateLimitCounter can
	// recompute X-RateLimit-Remaining after a refund.
	LocalKeyRateLimitConfiguredLimit = "rate_limit_configured_limit"

	// X-RateLimit-* response headers — GitHub / Stripe / Twilio convention.
	// Emitted on every response from the RateLimit middleware so an agent
	// can observe its remaining budget without parsing an error body. The
	// "Reset" value is the Unix seconds timestamp at which the daily
	// counter rolls over (midnight UTC next).
	rateLimitHeaderLimit     = "X-RateLimit-Limit"
	rateLimitHeaderRemaining = "X-RateLimit-Remaining"
	rateLimitHeaderReset     = "X-RateLimit-Reset"
)

// RateLimitConfig configures rate limiting behaviour.
type RateLimitConfig struct {
	// Limit is the maximum number of requests allowed per day per fingerprint.
	Limit int
	// KeyPrefix is prepended to the Redis key. Defaults to "rl".
	KeyPrefix string
}

// RateLimit returns a middleware that checks a per-fingerprint-per-day Redis counter.
// It does NOT return 429 — it sets a context flag so handlers can apply their own CTA logic.
// On Redis error the middleware fails open and logs the error.
func RateLimit(rdb *redis.Client, cfg RateLimitConfig) fiber.Handler {
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "rl"
	}
	if cfg.Limit == 0 {
		cfg.Limit = 100
	}

	return func(c *fiber.Ctx) error {
		fp := GetFingerprint(c)
		if fp == "" {
			return c.Next()
		}

		now := time.Now().UTC()
		date := now.Format("2006-01-02")
		key := fmt.Sprintf("%s:%s:%s", cfg.KeyPrefix, fp, date)

		// Stash the configured cap up-front. Available even on the fail-open
		// path so downstream readers (RefundRateLimitCounter) can still
		// recompute X-RateLimit-Remaining on Redis-degraded responses.
		c.Locals(LocalKeyRateLimitConfiguredLimit, int64(cfg.Limit))

		count, err := incrementWithExpiry(c.Context(), rdb, key, 25*time.Hour)
		if err != nil {
			slog.Error("rate_limit.redis_error",
				"error", err,
				"key", key,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("rate_limit").Inc()
			// P2 (CIRCUIT-RETRY-AUDIT-2026-05-20): record the fail-open
			// trip so the "fail-open rate" alert fires when Redis is
			// flapping. Semantics are unchanged — we still let the
			// request through — but the metric makes the loss-of-rate-
			// limit visible.
			metrics.FailOpenEvents.WithLabelValues("redis_rate_limit", "redis_unavailable").Inc()
			// Fail open — do not block the request. We still set the
			// X-RateLimit-Limit header so the client sees the policy;
			// "remaining" is unknown so we omit it on the failure path.
			c.Set(rateLimitHeaderLimit, strconv.Itoa(cfg.Limit))
			c.Set(rateLimitHeaderReset, strconv.FormatInt(nextUTCMidnight(now).Unix(), 10))
			return c.Next()
		}

		c.Locals(LocalKeyRateLimitCount, count)
		// Stash the exact Redis key we just INCR'd so RefundRateLimitCounter
		// (called by the idempotency cache-hit path) can DECR the same key
		// without re-deriving the prefix/date format. Without this signal a
		// replay would burn a counter slot even though the cached response
		// is served from Redis — violating the published Idempotency-Key
		// replay contract (FINDING API-1, fix /api/internal/middleware/
		// idempotency.go cache-hit branches).
		c.Locals(LocalKeyRateLimitKey, key)
		if count > int64(cfg.Limit) {
			c.Locals(LocalKeyRateLimitExceeded, true)
			metrics.FingerprintAbuseBlocked.Inc()
		}

		// X-RateLimit-* response headers — emitted on every response so
		// callers (especially agents) can observe their daily budget.
		remaining := int64(cfg.Limit) - count
		if remaining < 0 {
			remaining = 0
		}
		c.Set(rateLimitHeaderLimit, strconv.Itoa(cfg.Limit))
		c.Set(rateLimitHeaderRemaining, strconv.FormatInt(remaining, 10))
		c.Set(rateLimitHeaderReset, strconv.FormatInt(nextUTCMidnight(now).Unix(), 10))

		return c.Next()
	}
}

// nextUTCMidnight returns the next UTC midnight after t — the moment the
// per-day rate-limit counter rolls over. Used to populate
// X-RateLimit-Reset (Unix seconds, per the GitHub/Twilio convention).
func nextUTCMidnight(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d+1, 0, 0, 0, 0, time.UTC)
}

// IsRateLimitExceeded reports whether the rate limit was exceeded for this request.
func IsRateLimitExceeded(c *fiber.Ctx) bool {
	v, _ := c.Locals(LocalKeyRateLimitExceeded).(bool)
	return v
}

// GetRateLimitCount returns the current daily counter value.
func GetRateLimitCount(c *fiber.Ctx) int64 {
	v, _ := c.Locals(LocalKeyRateLimitCount).(int64)
	return v
}

// RefundRateLimitCounter compensates the per-fingerprint daily counter that
// was incremented by RateLimit on the way in. Called from the Idempotency
// middleware on a cache HIT so a replayed (cached) response does NOT burn
// a rate-limit slot — the original (uncached) call already paid that cost.
//
// Why this exists (FINDING API-1, root cause @ internal/router/router.go:201
// + internal/middleware/idempotency.go:283–301): RateLimit is wired at
// app.Use scope and runs BEFORE the per-route Idempotency middleware, so by
// the time the cache-hit branch short-circuits the counter has already
// incremented. Without a compensating DECR an agent retrying a transient
// 5xx with the same Idempotency-Key would burn a fresh daily slot on every
// retry — silently violating the published Stripe-shape replay contract.
//
// Safety posture (per CEO memo "Option C"):
//   - Refund is bounded by the rate-limit counter only. The handler-internal
//     per-fingerprint provision-dedup cap (5/day, CLAUDE.md rule 6) is NOT
//     touched — that path runs in handler code, not here.
//   - The FIRST call still pays the cost (RateLimit INCR'd before we got
//     here). Only replays get refunded. A malicious agent reusing one
//     Idempotency-Key 100x gets amortised-cheaper attempts, NOT free
//     attempts — they still paid the first INCR.
//   - Fail open: any Redis error (or missing key in Locals) logs a WARN
//     and returns. We never block the cached response on a refund failure;
//     the counter just stays slightly elevated, which is the conservative
//     direction (CLAUDE.md convention #1).
//
// Side effect: when the refund succeeds and X-RateLimit-Remaining is already
// set on the response, we increment the header value by 1 so the agent sees
// the post-refund budget instead of the pre-refund value. If the header
// isn't set yet (the original RateLimit failed open) we leave it alone.
//
// Returns the post-refund count (0 if no refund was performed).
func RefundRateLimitCounter(c *fiber.Ctx, rdb *redis.Client) int64 {
	if rdb == nil {
		return 0
	}
	key, _ := c.Locals(LocalKeyRateLimitKey).(string)
	if key == "" {
		// No fingerprint, or RateLimit never ran on this route — nothing
		// to refund. Safe no-op.
		return 0
	}
	newCount, err := rdb.Decr(c.Context(), key).Result()
	if err != nil {
		slog.Warn("rate_limit.refund_failed",
			"error", err,
			"key", key,
			"request_id", GetRequestID(c),
		)
		metrics.RedisErrors.WithLabelValues("rate_limit_refund").Inc()
		return 0
	}
	// Guard against a refund that would push the counter negative —
	// e.g. if the same request somehow refunded twice. Redis DECR
	// happily goes negative; we clamp the published count at 0 and
	// trust the 25h TTL to clean up the row.
	if newCount < 0 {
		newCount = 0
	}
	c.Locals(LocalKeyRateLimitCount, newCount)
	// Recompute X-RateLimit-Remaining so the agent sees the credit.
	// Only do this if RateLimit set the configured-limit Local — if it
	// didn't (e.g. RateLimit never ran), we have nothing to recompute
	// against.
	if limit, ok := c.Locals(LocalKeyRateLimitConfiguredLimit).(int64); ok && limit > 0 {
		remaining := limit - newCount
		if remaining < 0 {
			remaining = 0
		}
		c.Set(rateLimitHeaderRemaining, strconv.FormatInt(remaining, 10))
	}
	// Drop the LocalKey so a second refund within the same request (e.g.
	// re-entrant middleware composition) becomes a safe no-op rather
	// than double-decrementing.
	c.Locals(LocalKeyRateLimitKey, "")
	metrics.IdempotencyReplayRefunded.WithLabelValues(c.Route().Path).Inc()
	return newCount
}

// incrementWithExpiry performs an atomic INCR + EXPIRE (only sets expiry on first increment).
//
// A nil rdb is treated as a Redis error, not a panic: RateLimit's caller
// fails open on any error returned here (CLAUDE.md convention #1 — a Redis
// outage, or here a missing client, must never block or crash the request).
// Before this guard a nil client SIGSEGV'd inside go-redis (*Client).Pipeline
// on the very first request — a misconfigured deploy would crash the whole
// API rather than degrade gracefully.
func incrementWithExpiry(ctx context.Context, rdb *redis.Client, key string, ttl time.Duration) (int64, error) {
	if rdb == nil {
		return 0, fmt.Errorf("redis client is nil")
	}
	pipe := rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, ttl)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("redis pipeline: %w", err)
	}

	count, err := incrCmd.Result()
	if err != nil {
		return 0, fmt.Errorf("incr result: %w", err)
	}
	return count, nil
}
