package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/metrics"
)

// idempotency.go — Stripe/AWS-style Idempotency-Key support for provisioning
// endpoints (/db/new, /cache/new, /nosql/new, /queue/new, /storage/new,
// /webhook/new, /deploy/new).
//
// Rationale: autonomous AI agents (Claude Code, Cursor, MCP) retry on
// transient errors. Without idempotency, each retry creates a duplicate
// resource — burning quota and creating cleanup work. The header is opaque
// and client-supplied (agents generate a UUID per logical attempt). When
// present, the first response is cached for 24h and replayed verbatim on
// any subsequent call carrying the same key.
//
// Middleware ordering (see internal/router/router.go for the per-route
// wiring): RateLimit runs at app.Use scope (global, before OptionalAuth),
// so by the time this middleware runs the per-fingerprint daily counter
// has already incremented. THIS IS DELIBERATE: a malicious agent must NOT
// be able to bypass rate limiting via Idempotency-Key reuse, so replays
// still consume rate budget. The original-call cost is borne by the
// counter on the FIRST request; replays add an extra increment, which is
// the conservative choice — the customer paid for the first call (in
// quota terms) but a key-reuse attacker doesn't get free attempts.
// Quota-walls inside handlers (CheckAndIncrementToken) similarly continue
// to fire on replay paths, but the replay short-circuits BEFORE the
// handler so the quota counter is unaffected — the cached response simply
// goes out the wire. Net effect: rate-limit budget = abuse-protected;
// quota budget = customer-friendly (no double-charge for retries).
//
// Cache key shape: idem:<scope>:<endpoint>:<sha256(key)> where <scope> is
// team_id when the caller is authenticated, otherwise fingerprint. This
// gives per-tenant key spaces; one team's key can't collide with another's.
//
// Cache value shape: JSON-serialised idemEntry (status code + body bytes
// + body-content-hash + content-type). Stored with 24h TTL.
//
// Replay contract: a hit replays the cached status + body + Content-Type
// verbatim and sets X-Idempotent-Replay: true. If the cached body-hash
// does NOT match the current request body, return 409 conflict (the agent
// reused a key for a different request — almost certainly a bug).
//
// Precedence vs handler-internal fingerprint dedup (W11, 2026-05-14): the
// middleware sits BEFORE the handler in the per-route chain (see
// internal/router/router.go), so a cached idempotency hit short-circuits
// before the handler's fingerprint-dedup branch ever runs. This is the
// load-bearing ordering for the W11 contract that Idempotency-Key wins
// against fingerprint dedup:
//   - With Idempotency-Key + cached: replay the cached token (whatever it
//     was on the first call), even if fingerprint dedup would now hand out
//     a different existing resource. X-Idempotent-Replay: true.
//   - With Idempotency-Key + no cache: handler runs; its fingerprint-dedup
//     branch may apply on the first call. The response is then cached so
//     subsequent same-key calls replay the same token.
//   - Without Idempotency-Key: handler's fingerprint-dedup is the only
//     dedup layer. X-Idempotent-Replay is NEVER set on this path — that
//     header is reserved exclusively for the idempotency middleware so
//     upstream agents can branch reliably on "this was a replay vs a
//     fingerprint dedup hit vs a fresh provision".
// E2E coverage: e2e/w11_hardening_e2e_test.go pins all three branches.
//
// 5xx responses are NOT cached so retries trigger fresh attempts; 2xx and
// 4xx ARE cached (a 402 quota_exceeded should replay so the agent sees
// the same upgrade prompt rather than retry-storming the wall).

const (
	// idempotencyHeader is the request header carrying the opaque key.
	idempotencyHeader = "Idempotency-Key"
	// idempotencyReplayHeader is set on replayed responses.
	idempotencyReplayHeader = "X-Idempotent-Replay"
	// idempotencyTTL is the cache lifetime — matches Stripe's 24h window.
	idempotencyTTL = 24 * time.Hour
	// idempotencyKeyMaxLen caps the client-supplied key. Stripe uses 255.
	idempotencyKeyMaxLen = 255
)

// idemEntry is the JSON shape persisted in Redis. It captures everything
// needed to replay the response verbatim (status, body, content-type) plus
// the request-body hash used to detect key-with-different-body misuse.
type idemEntry struct {
	StatusCode  int    `json:"s"`
	Body        []byte `json:"b"`
	ContentType string `json:"c"`
	BodyHash    string `json:"h"` // sha256 hex of the original request body
}

// Idempotency returns a Fiber handler that caches successful responses
// by an opaque Idempotency-Key header. When the header is absent the
// middleware is a no-op (backwards-compat for all existing callers).
//
// endpoint is a short stable identifier (e.g. "db.new") used to namespace
// the cache key — the same idempotency key sent to /db/new and /cache/new
// MUST NOT collide.
func Idempotency(rdb *redis.Client, endpoint string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		rawKey := c.Get(idempotencyHeader)
		if rawKey == "" {
			return c.Next()
		}

		key := strings.TrimSpace(rawKey)
		if err := validateIdempotencyKey(key); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok":      false,
				"error":   "invalid_idempotency_key",
				"message": err.Error(),
			})
		}

		// Scope: team_id when authenticated, fingerprint when anonymous.
		// Falls back to "anon" if neither is populated (no fingerprint
		// middleware ran, no auth) — still gives correct semantics, just
		// in a degenerate shared keyspace. That can't happen in production
		// since Fingerprint() runs at app.Use scope.
		scope := GetTeamID(c)
		if scope == "" {
			scope = GetFingerprint(c)
		}
		if scope == "" {
			scope = "anon"
		}

		keyHash := sha256Hex(key)
		cacheKey := fmt.Sprintf("idem:%s:%s:%s", scope, endpoint, keyHash)

		// Request body hash — used to detect "same key, different body" misuse.
		// c.Body() returns []byte, may be empty for some endpoints (e.g.
		// /webhook/new accepts an empty body). Empty body hashes to a stable
		// constant, which is the correct behaviour for "two empty requests
		// with the same key should be deduped".
		reqBody := c.Body()
		reqBodyHash := sha256Hex(string(reqBody))

		ctx := c.Context()

		// Check for an existing entry. Redis errors are fail-open — a
		// Redis outage must not block provisioning (same fail-open posture
		// as the rate-limit and quota middleware). When the lookup fails
		// we proceed without idempotency for this request; the caller may
		// see a duplicate resource if they retry, which is strictly less
		// bad than blocking provisioning entirely.
		raw, err := rdb.Get(ctx, cacheKey).Result()
		if err != nil && !errors.Is(err, redis.Nil) {
			slog.Warn("idempotency.redis_get_failed",
				"error", err,
				"endpoint", endpoint,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("idempotency").Inc()
			return c.Next()
		}

		if err == nil {
			// Cache hit — replay or conflict.
			var entry idemEntry
			if jerr := json.Unmarshal([]byte(raw), &entry); jerr != nil {
				// Corrupt cache entry — treat as miss and overwrite below.
				slog.Warn("idempotency.cache_unmarshal_failed",
					"error", jerr, "endpoint", endpoint)
			} else {
				if entry.BodyHash != reqBodyHash {
					return c.Status(fiber.StatusConflict).JSON(fiber.Map{
						"ok":      false,
						"error":   "idempotency_key_conflict",
						"message": "Idempotency-Key already used with a different body",
					})
				}
				// Replay verbatim.
				c.Set(idempotencyReplayHeader, "true")
				if entry.ContentType != "" {
					c.Set(fiber.HeaderContentType, entry.ContentType)
				}
				return c.Status(entry.StatusCode).Send(entry.Body)
			}
		}

		// Miss — run the handler, then cache the response.
		if err := c.Next(); err != nil {
			return err
		}

		status := c.Response().StatusCode()
		// Don't cache 5xx — retries should produce fresh attempts.
		if status >= 500 {
			return nil
		}

		// Snapshot the response body. Fiber/fasthttp owns the underlying
		// buffer and may pool it after the request returns, so copy.
		body := append([]byte(nil), c.Response().Body()...)
		ct := string(c.Response().Header.ContentType())

		entry := idemEntry{
			StatusCode:  status,
			Body:        body,
			ContentType: ct,
			BodyHash:    reqBodyHash,
		}
		payload, jerr := json.Marshal(entry)
		if jerr != nil {
			slog.Warn("idempotency.marshal_failed",
				"error", jerr, "endpoint", endpoint)
			return nil
		}

		// Set with NX semantics is tempting (only one writer wins on
		// race) but the trade-off is that two concurrent first-callers
		// with the same key would each provision a resource. The 5xx-not-
		// cached rule means most race losers don't get cached anyway;
		// the bigger picture is that race-window dedup is a Phase 2
		// concern and the per-fingerprint rate limit caps the blast
		// radius today.
		if serr := rdb.Set(context.Background(), cacheKey, payload, idempotencyTTL).Err(); serr != nil {
			slog.Warn("idempotency.redis_set_failed",
				"error", serr,
				"endpoint", endpoint,
				"request_id", GetRequestID(c),
			)
			metrics.RedisErrors.WithLabelValues("idempotency").Inc()
			// Fall through — the response is already on the wire.
		}
		return nil
	}
}

// validateIdempotencyKey enforces the wire-format constraints from the
// spec: 1-255 ASCII printable characters. Anything outside that range is
// rejected with 400 rather than silently bypassing idempotency.
func validateIdempotencyKey(key string) error {
	if key == "" {
		return errors.New("Idempotency-Key must not be empty")
	}
	if len(key) > idempotencyKeyMaxLen {
		return fmt.Errorf("Idempotency-Key exceeds %d-character limit", idempotencyKeyMaxLen)
	}
	for _, r := range key {
		// ASCII printable: 0x20 (space) through 0x7E (~).
		if r < 0x20 || r > 0x7E {
			return errors.New("Idempotency-Key must contain only ASCII printable characters")
		}
	}
	return nil
}

// sha256Hex returns the hex-encoded SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
