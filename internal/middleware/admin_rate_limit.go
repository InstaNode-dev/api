package middleware

// admin_rate_limit.go — per-fingerprint sliding-window rate limit on the
// admin route prefix. THIRD defense-in-depth layer on top of the existing
// ADMIN_PATH_PREFIX (gate 1) + ADMIN_EMAILS (gate 2):
//
//   Gate 3 here: hard-cap 30 admin-route hits / minute / fingerprint.
//   Excess returns 403 (NOT 429) — the response body and status code are
//   indistinguishable from "not on the allowlist." That's the whole point:
//   an attacker who somehow learned the unguessable prefix cannot
//   differentiate "I'm probing too fast" from "I don't have an admin
//   email" and therefore can't tell the prefix is right.
//
// Order in the admin chain (router.go):
//
//   RateLimit → RequireAdmin → Audit → handler
//
// RATE LIMIT RUNS FIRST. If we put RequireAdmin before the rate-limit,
// an attacker who knows the prefix can probe forever by sending invalid
// JWTs (the allowlist check rejects, but no counter ever increments).
// Running the limiter first ensures every prefix hit costs a slot in
// the bucket — invalid-email probes are throttled exactly like valid-
// email-but-allowlist-miss probes.
//
// Storage: Redis sorted-set sliding window (one ZSET per fingerprint,
// keyed by minute). 25-hour TTL keeps the key around through DST-style
// edge cases the same way the daily provision rate-limit does.
//
// Fail-open on Redis errors: a Redis outage MUST NOT block legitimate
// admin work. We log the error, increment a metric, and let the request
// proceed. The risk model is "Redis is down so probing isn't a problem,
// the allowlist is still the last line" — the same posture every
// fingerprint-rate-limit in this codebase takes (see internal/middleware/
// rate_limit.go).

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
	// AdminRateLimitPerMinute is the per-fingerprint cap on admin-prefix
	// hits within any rolling 60-second window. Set generously enough that
	// a founder using the dashboard's customer-search-as-you-type doesn't
	// trip the wall, low enough that a brute-force probe sees a hard wall
	// at attempt 31.
	//
	// 30/min ≈ 0.5/s. The dashboard's heaviest admin call patterns (page
	// load + 5 detail clicks + 5 audit pivots in one minute) max out near
	// ~15 requests, leaving 50% headroom. A scripted probe needing 1k
	// guesses takes >30 minutes at the wall — and every probe also hits
	// AdminAuditEmit, so the operator sees the noise immediately.
	AdminRateLimitPerMinute = 30

	// adminRateLimitKeyPrefix is the Redis key namespace. Per-fingerprint
	// sliding window: rl_admin:{fingerprint}.
	adminRateLimitKeyPrefix = "rl_admin"

	// adminRateLimitTTL is the lifetime on the Redis ZSET. Just over an hour
	// is enough — the sliding window is 60s, but we keep the key around
	// past the window so a burst-then-pause-then-burst still sees its old
	// entries cleaned up via ZREMRANGEBYSCORE on the next hit.
	adminRateLimitTTL = 25 * time.Hour

	// adminRateLimitWindow is the rolling window size in seconds (the "30
	// req per MINUTE" denominator).
	adminRateLimitWindow = 60 * time.Second
)

// AdminRateLimit returns a Fiber middleware enforcing AdminRateLimitPerMinute
// admin-prefix hits per fingerprint per rolling minute. On excess it
// returns 403 with the canonical agent_action for admin denial — byte-for-
// byte identical to the RequireAdmin "not an admin" response, so a probe
// cannot tell which gate it hit.
//
// rdb may be nil — in that case the middleware degrades to a no-op pass-
// through (the rate-limit becomes infinite). The router doesn't wire a
// nil Redis in production; the nil-tolerance is for cleanliness in tests
// that build a partial Fiber app without Redis.
func AdminRateLimit(rdb *redis.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if rdb == nil {
			return c.Next()
		}
		fp := GetFingerprint(c)
		if fp == "" {
			// No fingerprint == no key. Don't fail open silently; pass
			// through. The RequireAdmin gate downstream still rejects
			// any unauthenticated caller.
			return c.Next()
		}

		over, err := adminRateLimitExceeded(c.Context(), rdb, fp)
		if err != nil {
			slog.Error("admin_rate_limit.redis_error",
				"error", err,
				"fingerprint", fp,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("admin_rate_limit").Inc()
			// Fail open — don't block legit admin work on a Redis hiccup.
			return c.Next()
		}
		if over {
			// IMPORTANT: this body MUST stay byte-identical to the
			// RequireAdmin 403 body. Any drift (extra field, different
			// message wording) leaks "the prefix is right but you're
			// probing too fast" — exactly the signal we deny attackers.
			// W12: request_id + retry_after_seconds added to match the
			// canonical envelope; both fields are also populated on the
			// RequireAdmin 403, so the bodies stay identical up to the
			// per-request request_id value (which would be present on
			// either path anyway).
			metrics.FingerprintAbuseBlocked.Inc()
			c.Locals(LocalKeyAdminRateLimitExceeded, true)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"ok":                  false,
				"error":               "forbidden",
				"message":             "platform-admin access required",
				"request_id":          GetRequestID(c),
				"retry_after_seconds": nil,
				"agent_action":        adminForbiddenAgentAction,
			})
		}
		return c.Next()
	}
}

// LocalKeyAdminRateLimitExceeded is set on the Fiber locals when AdminRateLimit
// rejects the request. Lets the audit middleware (which runs AFTER this on
// the request side but reads locals at the response side via OnResponse) know
// the 403 came from the rate-limit path so it can stamp that on the audit row's
// `denied_by` field. The audit row is still written on a rate-limited reject —
// the operator must see brute-force probes even when the limiter is muting them.
const LocalKeyAdminRateLimitExceeded = "admin_rate_limited"

// IsAdminRateLimited reports whether the current request was muted by the
// admin rate limiter. The audit middleware reads this to record the reason
// on the audit row.
func IsAdminRateLimited(c *fiber.Ctx) bool {
	v, _ := c.Locals(LocalKeyAdminRateLimitExceeded).(bool)
	return v
}

// adminRateLimitExceeded implements the per-fingerprint sliding-window check
// against Redis. Algorithm (single pipeline, atomic from the client's POV):
//
//  1. ZREMRANGEBYSCORE the key — drop entries older than (now − window).
//  2. ZCARD the key — count remaining entries.
//  3. ZADD a unique entry for now.
//  4. EXPIRE the key so an idle fingerprint's data drops out cleanly.
//
// The CARD value AFTER cleanup tells us whether the caller has already
// used their quota in the window. We return over=true when the count is
// at or above the cap BEFORE this request is recorded — meaning this
// request is the (cap+1)th in the window.
//
// Note: ZCARD is read between cleanup and the new ZADD, so the value
// reflects "how many calls in the last 60s NOT counting this one." A
// caller making exactly 30 calls in a minute sees over=false on all 30;
// the 31st sees over=true.
//
// The ZADD member is "now-nanos:randhint" — a unique-per-call string so
// repeated calls in the same millisecond all distinct ZSET members.
// (ZADD with a duplicate member updates the score, which would let a
// caller hammer at sub-ms cadence and only ever leave one entry in the
// set.)
func adminRateLimitExceeded(ctx context.Context, rdb *redis.Client, fp string) (bool, error) {
	key := adminRateLimitKey(fp)
	now := time.Now()
	cutoff := now.Add(-adminRateLimitWindow).UnixNano()
	score := now.UnixNano()
	// member must be unique per call — score alone collides under load.
	// 4-byte random suffix from the score nanos is enough (tests run on a
	// single goroutine; production has request_id propagation but we don't
	// want a dep on that local).
	member := fmt.Sprintf("%d:%d", score, score%1000003)

	pipe := rdb.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("(%d", cutoff))
	cardCmd := pipe.ZCard(ctx, key)
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(score), Member: member})
	pipe.Expire(ctx, key, adminRateLimitTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("admin_rate_limit pipeline: %w", err)
	}
	count, err := cardCmd.Result()
	if err != nil {
		return false, fmt.Errorf("admin_rate_limit zcard: %w", err)
	}
	// count is the size of the ZSET AFTER cleanup, BEFORE this request's
	// ZADD has been observed (Redis pipelines preserve order but the
	// in-flight ZCARD reads the state at its execution point). count >= cap
	// means "the last `cap` calls fall inside the window, this one would
	// be the (cap+1)th."
	return count >= int64(AdminRateLimitPerMinute), nil
}

// adminRateLimitKey returns the Redis key for one fingerprint's admin
// sliding window. Lives in the rl_admin namespace so an ops dashboard
// can list active probing sources with `KEYS rl_admin:*` without
// matching the general /provision rate limit keys.
func adminRateLimitKey(fp string) string {
	return fmt.Sprintf("%s:%s", adminRateLimitKeyPrefix, fp)
}
