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

		count, err := incrementWithExpiry(c.Context(), rdb, key, 25*time.Hour)
		if err != nil {
			slog.Error("rate_limit.redis_error",
				"error", err,
				"key", key,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("rate_limit").Inc()
			// Fail open — do not block the request. We still set the
			// X-RateLimit-Limit header so the client sees the policy;
			// "remaining" is unknown so we omit it on the failure path.
			c.Set(rateLimitHeaderLimit, strconv.Itoa(cfg.Limit))
			c.Set(rateLimitHeaderReset, strconv.FormatInt(nextUTCMidnight(now).Unix(), 10))
			return c.Next()
		}

		c.Locals(LocalKeyRateLimitCount, count)
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
