package middleware

import (
	"context"
	"fmt"
	"log/slog"
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

		date := time.Now().UTC().Format("2006-01-02")
		key := fmt.Sprintf("%s:%s:%s", cfg.KeyPrefix, fp, date)

		count, err := incrementWithExpiry(c.Context(), rdb, key, 25*time.Hour)
		if err != nil {
			slog.Error("rate_limit.redis_error",
				"error", err,
				"key", key,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("rate_limit").Inc()
			// Fail open — do not block the request
			return c.Next()
		}

		c.Locals(LocalKeyRateLimitCount, count)
		if count > int64(cfg.Limit) {
			c.Locals(LocalKeyRateLimitExceeded, true)
			metrics.FingerprintAbuseBlocked.Inc()
		}

		return c.Next()
	}
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
func incrementWithExpiry(ctx context.Context, rdb *redis.Client, key string, ttl time.Duration) (int64, error) {
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
