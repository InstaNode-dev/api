package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"instant.dev/internal/metrics"
)

// idempotency.go — Stripe/AWS-style Idempotency-Key support for provisioning
// endpoints (/db/new, /cache/new, /nosql/new, /queue/new, /storage/new,
// /webhook/new, /deploy/new) PLUS a body-fingerprint fallback that protects
// every create endpoint against accidental double-creation even when the
// caller didn't opt in via the header.
//
// Rationale: autonomous AI agents (Claude Code, Cursor, MCP) retry on
// transient errors. Browsers double-tap on flaky mobile networks. Forms
// resubmit on the back button. Without idempotency, each retry creates a
// duplicate resource — burning quota and creating cleanup work. The header
// is opaque and client-supplied (agents generate a UUID per logical
// attempt). When present, the first response is cached for 24h and
// replayed verbatim on any subsequent call carrying the same key.
//
// Fingerprint-fallback contract (2026-05-14, this file): when the header
// is ABSENT, the middleware synthesises a fallback key from
// sha256(scope || "|" || route_pattern || "|" || canonical_body) and
// caches the response for 120s. Long enough to absorb double-clicks and
// fast retry storms; short enough that an honest second creation 5
// minutes later doesn't accidentally replay. Callers who want exactly-
// once across longer windows must pass an explicit Idempotency-Key.
// The response carries X-Idempotency-Source: explicit|fingerprint|miss
// so debuggers can see which path matched.
//
// Middleware ordering (see internal/router/router.go for the per-route
// wiring): RateLimit runs at app.Use scope (global, before OptionalAuth),
// so by the time this middleware runs the per-fingerprint daily counter
// has already incremented. To honor the published Stripe-shape replay
// contract — same Idempotency-Key replays the cached response without
// burning a fresh rate-limit slot — every cache HIT path below calls
// RefundRateLimitCounter (single Redis DECR) BEFORE sending the cached
// response. The FIRST call still pays the cost (the original INCR), so
// an attacker reusing one key 100× gets amortised-cheaper attempts, NOT
// free attempts (FINDING API-1, CEO Option C, 2026-05-29). The handler-
// internal per-fingerprint provision-dedup cap (5/day, CLAUDE.md rule 6)
// is NOT touched by the refund — that abuse signal lives in handler
// code and is independent of the request-rate-limit counter.
//
// Quota-walls inside handlers (CheckAndIncrementToken) continue to fire
// on replay paths, but the replay short-circuits BEFORE the handler so
// the quota counter is unaffected — the cached response simply goes out
// the wire. Net effect: rate-limit budget = refunded on replay (Stripe
// contract); fingerprint provision-dedup = abuse-protected (unchanged);
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
//     a different existing resource. X-Idempotent-Replay: true,
//     X-Idempotency-Source: explicit.
//   - With Idempotency-Key + no cache: handler runs; its fingerprint-dedup
//     branch may apply on the first call. The response is then cached so
//     subsequent same-key calls replay the same token.
//   - Without Idempotency-Key (fingerprint-fallback path, 2026-05-14):
//     the middleware's own body-fingerprint cache may replay the previous
//     response (X-Idempotent-Replay: true, X-Idempotency-Source:
//     fingerprint). On a miss, the handler runs; its handler-internal
//     fingerprint-dedup branch may still apply on the 6th+ provision.
//     Handler-only dedup paths produce X-Idempotency-Source: miss (no
//     replay header) so upstream agents can still distinguish "middleware
//     replayed" from "handler returned existing token" from "fresh
//     provision".
// E2E coverage: e2e/w11_hardening_e2e_test.go pins the explicit branches;
// e2e/idempotency_fingerprint_e2e_test.go pins the fallback path.
//
// 5xx responses are NOT cached so retries trigger fresh attempts; 2xx and
// 4xx ARE cached (a 402 quota_exceeded should replay so the agent sees
// the same upgrade prompt rather than retry-storming the wall).

// IsResponseWrittenErr reports whether err is the handlers.ErrResponseWritten
// sentinel — the marker respondError* returns after committing a structured
// 4xx/5xx body to the wire. The handlers package registers the real check
// via init() (see handlers/helpers.go) to avoid an import cycle: handlers
// imports middleware, so middleware cannot import handlers directly.
//
// Default returns false so test packages that don't import handlers (none
// of the middleware-package tests do today) get the pre-BB2-D5 behaviour
// where any handler error bypasses caching. Production routes always
// import handlers indirectly via router/router.go, so the init() fires.
var IsResponseWrittenErr = func(err error) bool { return false }

const (
	// idempotencyHeader is the request header carrying the opaque key.
	idempotencyHeader = "Idempotency-Key"
	// idempotencyReplayHeader is set on replayed responses.
	idempotencyReplayHeader = "X-Idempotent-Replay"
	// idempotencySourceHeader is set on every response that the middleware
	// touches, signalling which dedup path matched: "explicit" when the
	// caller passed an Idempotency-Key (whether cached or fresh),
	// "fingerprint" when the body-fingerprint fallback matched a cached
	// entry, "miss" when the fingerprint path ran the handler fresh.
	idempotencySourceHeader = "X-Idempotency-Source"
	// idempotencyTTL is the cache lifetime — matches Stripe's 24h window
	// for explicit-key requests. The fingerprint fallback uses
	// idempotencyFingerprintTTL instead (much shorter — see below).
	idempotencyTTL = 24 * time.Hour
	// idempotencyFingerprintTTL is the lifetime of an auto-synthesised
	// fingerprint cache entry. 120s is the smallest window that absorbs
	// double-clicks, mobile-network retries, and 5xx retry storms while
	// staying short enough that a second honest creation a few minutes
	// later doesn't accidentally replay. Callers who need true
	// exactly-once over longer windows MUST pass an explicit
	// Idempotency-Key (which gets the full 24h cache).
	idempotencyFingerprintTTL = 120 * time.Second
	// idempotencyKeyMaxLen caps the client-supplied key. Stripe uses 255.
	idempotencyKeyMaxLen = 255
	// idempotencyInflightTTL bounds an in-flight reservation marker (BugBash
	// 2026-06-02 #21). It must exceed the slowest synchronous handler — a
	// real provision (provisionDB/Cache/NoSQL runs in-request) can take
	// ~10-20s — so a concurrent retry is correctly told "in progress" rather
	// than racing past a too-early-expired marker. It is also the worst-case
	// self-heal window if the process dies mid-handler before the marker is
	// overwritten or deleted.
	idempotencyInflightTTL = 60 * time.Second

	// X-Idempotency-Source values.
	idempotencySourceExplicit    = "explicit"
	idempotencySourceFingerprint = "fingerprint"
	idempotencySourceMiss        = "miss"
)

// idemEntry is the JSON shape persisted in Redis. It captures everything
// needed to replay the response verbatim (status, body, content-type) plus
// the request-body hash used to detect key-with-different-body misuse.
type idemEntry struct {
	StatusCode  int    `json:"s"`
	Body        []byte `json:"b"`
	ContentType string `json:"c"`
	BodyHash    string `json:"h"` // sha256 hex of the original request body
	// InFlight marks a reservation placeholder written (via SETNX) the
	// moment a cache-miss request begins running the handler, BEFORE the
	// real response exists. A concurrent same-key request that reads this
	// marker must NOT re-run the handler — it returns 409
	// idempotency_key_in_progress instead. The marker is overwritten by the
	// real entry when the handler completes (or deleted if the response is
	// non-cacheable), and self-expires after idempotencyInflightTTL if the
	// process dies mid-handler. Closes the check-then-act double-create race
	// (BugBash 2026-06-02 #21).
	InFlight bool `json:"f,omitempty"`
}

// mutableErrorCodes lists machine-readable `error` strings whose 4xx
// resolution can flip BEFORE the explicit-key 24h cache TTL elapses,
// so caching them silently strands the agent on the stale failure.
//
// BUG-API-238 (QA 2026-05-29): the canonical case is
// `free_tier_recycle_requires_claim`. Sequence:
//
//  1. Agent calls POST /db/new with Idempotency-Key K1. The recycle gate
//     fires → 402 free_tier_recycle_requires_claim cached against K1.
//  2. User follows the claim_url and successfully claims (POST /claim).
//     The recycle gate state is now CLEARED — a fresh /db/new without
//     a key would succeed.
//  3. Agent retries the original /db/new with Idempotency-Key K1. The
//     pre-fix path replays the cached 402 verbatim, even though the
//     gate would now wave the caller through. Agent thinks the claim
//     failed; user thinks the platform is broken.
//
// Excluding these codes from caching restores the Stripe-shape contract
// ("same key replays the same response") in the spirit it was written:
// a STABLE outcome is replayed. A 402 that disappears the moment the
// user takes 30 seconds to claim is not a stable outcome.
//
// We do NOT exclude generic `quota_exceeded` / `upgrade_required` /
// `provision_limit_reached` — those resolve on a calendar boundary
// (next UTC day) or a payment event, both of which are outside the
// agent's reach inside the 24h key TTL. The recycle gate is the
// distinguishing case: a user-initiated action a few seconds later
// clears it.
//
// The list is small on purpose. Adding a code here means "this gate
// can clear inside 24h without server-side state change" — which is
// the actual cache-coherence boundary. Any future addition needs a
// regression test that exercises the same-key-retry-after-resolution
// path.
var mutableErrorCodes = map[string]struct{}{
	"free_tier_recycle_requires_claim": {},
}

// shouldCacheResponse decides whether a non-5xx response should be
// written to the idempotency cache. Success (<400) always caches —
// that's the Stripe contract. 4xx responses cache UNLESS the body's
// `error` field is in mutableErrorCodes (BUG-API-238).
//
// JSON peek is non-strict: any parse error / non-JSON body / missing
// `error` field falls back to caching (the pre-fix behaviour). Only a
// well-formed envelope whose `error` is listed gets skipped, so the
// helper degrades safely on unexpected bodies.
func shouldCacheResponse(status int, body []byte, contentType string) bool {
	// Success responses always cache — the Stripe-shape contract guarantees
	// the agent can replay them. Mutability only matters for failures the
	// caller might re-resolve.
	if status < 400 {
		return true
	}
	// Quick rejects: non-JSON bodies (e.g. text/html 4xx) can't carry the
	// `error` field shape we filter on, so default-cache them.
	if !strings.Contains(contentType, "json") {
		return true
	}
	if len(body) == 0 {
		return true
	}
	// Peek the `error` field. Use a minimal struct to avoid pulling in the
	// handlers package's ErrorResponse (which would create a circular
	// import — handlers depends on middleware).
	var peek struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		// Malformed JSON body — defer to default (cache). The handler
		// emitted bytes the test suite is responsible for catching.
		return true
	}
	if _, mutable := mutableErrorCodes[peek.Error]; mutable {
		return false
	}
	return true
}

// Idempotency returns a Fiber handler that dedups duplicate POSTs via two
// layered mechanisms:
//
//  1. Explicit Idempotency-Key header (Stripe-shape, 24h TTL). When the
//     caller passes a UUID-shaped key, the first response is cached and
//     replayed verbatim on every subsequent call with the same key.
//  2. Body-fingerprint fallback (120s TTL). When the header is absent the
//     middleware synthesises a key from sha256(scope || route || body).
//     Absorbs accidental double-clicks, mobile double-taps, agent retries
//     on transient 5xx, and reverse-proxy retries on network blips.
//
// Both paths set X-Idempotency-Source: explicit|fingerprint|miss so the
// caller (and any debugging tee) can see which path matched.
//
// endpoint is a short stable identifier (e.g. "db.new") used to namespace
// the cache key — the same idempotency key sent to /db/new and /cache/new
// MUST NOT collide. The fingerprint path additionally namespaces by the
// route pattern (c.Route().Path) so /db/new and /cache/new with the same
// empty body never share a cache slot.
func Idempotency(rdb *redis.Client, endpoint string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Fail open when Redis is unavailable. A nil client (a
		// misconfigured deploy) would otherwise SIGSEGV inside go-redis
		// on the first request to reach idempotencyExplicit/Fingerprint —
		// crashing the whole API instead of degrading gracefully.
		// Idempotency is a best-effort dedupe layer, never a correctness
		// gate, so skipping it on no-Redis is safe (CLAUDE.md convention #1).
		if rdb == nil {
			return c.Next()
		}

		rawKey := c.Get(idempotencyHeader)
		// B18-M1 (BugBash 2026-05-20): a literally-empty Idempotency-Key
		// header value (e.g. `Idempotency-Key:` with nothing after, or
		// `Idempotency-Key:   `) used to silently fall through to the
		// fingerprint fallback path — the caller's "I want exactly-once"
		// intent was discarded without signal. The OpenAPI spec already
		// documents `invalid_idempotency_key` 400 for malformed keys; an
		// empty value is the most-common malformed shape. Reject up-front
		// so the caller learns immediately. We use raw c.Get() (not the
		// TrimSpace'd value) to detect "header present but empty/blank"
		// distinctly from "header omitted" — Fiber returns "" for both
		// cases via c.Get, so we have to look at the raw headers map.
		headerPresent := len(c.Request().Header.Peek(idempotencyHeader)) > 0
		if headerPresent && strings.TrimSpace(rawKey) == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"ok":      false,
				"error":   "invalid_idempotency_key",
				"message": "Idempotency-Key header is present but its value is empty or blank",
			})
		}

		// Compute the scope used to namespace cache keys. team_id when
		// authenticated, network fingerprint (sha256(/24-subnet + ASN)
		// from middleware.Fingerprint) when anonymous, "anon" as a last
		// resort if neither is populated — which can't happen in
		// production since Fingerprint() runs at app.Use scope.
		scope := GetTeamID(c)
		if scope == "" {
			scope = GetFingerprint(c)
		}
		if scope == "" {
			scope = "anon"
		}

		// Branch 1: explicit Idempotency-Key path. The validation, scope,
		// and cache mechanics here are unchanged from the pre-fingerprint
		// implementation — DO NOT alter TTL or key shape; that's an
		// existing contract that callers depend on. The only behaviour
		// added in this branch is the X-Idempotency-Source: explicit
		// header.
		if rawKey != "" {
			return idempotencyExplicit(c, rdb, endpoint, scope, rawKey)
		}

		// Branch 2: body-fingerprint fallback. The synthesised key is
		// sha256(scope || "|" || route_pattern || "|" || canonical_body)
		// with a 120s TTL. The route pattern (not the full URL) is the
		// namespace so /db/new vs /cache/new vs /webhook/new can't collide
		// even with the same empty body. Multipart endpoints (notably
		// /deploy/new) get a special canonicaliser that hashes the
		// tarball + sorted form fields instead of the raw multipart blob.
		return idempotencyFingerprint(c, rdb, endpoint, scope)
	}
}

// respondIdempotencyInProgress returns the 409 a request gets when it finds an
// in-flight reservation marker for its key (BugBash 2026-06-02 #21). The
// envelope mirrors the idempotency_key_conflict 409 (ok/error/message/
// request_id/retry_after_seconds/agent_action) but is RETRYABLE: unlike a
// body-mismatch conflict, the right move is to wait and retry the SAME key —
// the original request's response will be replayed once it completes.
func respondIdempotencyInProgress(c *fiber.Ctx) error {
	return c.Status(fiber.StatusConflict).JSON(fiber.Map{
		"ok":                  false,
		"error":               "idempotency_key_in_progress",
		"message":             "A request with this Idempotency-Key is still being processed.",
		"request_id":          GetRequestID(c),
		"retry_after_seconds": 2,
		"agent_action":        "Another request with the same Idempotency-Key is still in flight. Do NOT mint a new key — wait ~2s and retry the SAME key; the original response will be replayed once it completes. See https://instanode.dev/docs/idempotency.",
	})
}

// reserveInflight best-effort places an in-flight marker at cacheKey via SETNX,
// so a concurrent same-key request that arrives after this point reads the
// marker and returns 409 in_progress instead of double-running the handler
// (BugBash 2026-06-02 #21). Fire-and-forget: a SETNX error or a lost sub-
// millisecond race just means the marker isn't placed, and the request falls
// back to the documented best-effort dedup posture (run the handler; the GET
// hit-block still catches the common case where the other request reserved
// first). The marker is overwritten by the real entry on completion, or
// cleared on a non-cacheable response.
func reserveInflight(ctx context.Context, rdb *redis.Client, cacheKey, reqBodyHash string) {
	// Marshal of this fixed-shape struct cannot fail; the marker is best-effort
	// regardless, so we ignore the error and let SETNX no-op on a nil payload.
	marker, _ := json.Marshal(idemEntry{InFlight: true, BodyHash: reqBodyHash})
	_ = rdb.SetNX(ctx, cacheKey, marker, idempotencyInflightTTL).Err()
}

// idempotencyExplicit handles the Stripe-shape Idempotency-Key path.
// Extracted from the main Idempotency wrapper so the fingerprint-fallback
// branch can live alongside it without nesting another layer of if-blocks.
func idempotencyExplicit(c *fiber.Ctx, rdb *redis.Client, endpoint, scope, rawKey string) error {
	key := strings.TrimSpace(rawKey)
	if err := validateIdempotencyKey(key); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"ok":      false,
			"error":   "invalid_idempotency_key",
			"message": err.Error(),
		})
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

	// Mark every response on the explicit path so callers can branch on
	// "did the middleware see my key?" (vs. a typo that fell through to
	// the fingerprint fallback).
	c.Set(idempotencySourceHeader, idempotencySourceExplicit)

	ctx := c.Context()
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
		var entry idemEntry
		if jerr := json.Unmarshal([]byte(raw), &entry); jerr != nil {
			slog.Warn("idempotency.cache_unmarshal_failed",
				"error", jerr, "endpoint", endpoint)
		} else {
			if entry.InFlight {
				// A concurrent request with this key is still running (it
				// placed this reservation marker). Don't run the handler a
				// second time (BugBash #21) — tell the caller to retry the
				// same key shortly. No rate-limit refund: nothing was served.
				return respondIdempotencyInProgress(c)
			}
			if entry.BodyHash != reqBodyHash {
				// 409 is a genuine error response, not a replay — DO NOT
				// refund the rate-limit counter here. The agent did the
				// wrong thing (reused a key for a different body) and
				// should still pay the cost of that mistake.
				//
				// BUG-API-013/406: every 4xx must carry the canonical
				// envelope — request_id + agent_action — so an agent
				// inspecting this 409 gets the same shape as the
				// handler-emitted 400/402/etc. branches. The agent_action
				// tells the agent to mint a NEW Idempotency-Key for the
				// new body, not retry the same key (which would keep
				// returning 409). retry_after_seconds is null: the
				// conflict is permanent for this (key, body) pair — only
				// re-keying resolves it.
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{
					"ok":                  false,
					"error":               "idempotency_key_conflict",
					"message":             "Idempotency-Key already used with a different body",
					"request_id":          GetRequestID(c),
					"retry_after_seconds": nil,
					"agent_action":        "Tell the user this Idempotency-Key is already bound to a different request body. Mint a NEW Idempotency-Key (any RFC 4122 UUID) for the new body and retry — see https://instanode.dev/docs/idempotency.",
				})
			}
			// Cache HIT — refund the rate-limit slot RateLimit burned on
			// the way in (FINDING API-1, Option C). Fail-open: a refund
			// error logs WARN but never blocks the cached response.
			RefundRateLimitCounter(c, rdb)
			c.Set(idempotencyReplayHeader, "true")
			if entry.ContentType != "" {
				c.Set(fiber.HeaderContentType, entry.ContentType)
			}
			return c.Status(entry.StatusCode).Send(entry.Body)
		}
	}

	// MISS — reserve the key (SETNX in-flight marker) before running the
	// handler so a concurrent same-key request reads the marker and 409s
	// instead of double-creating (BugBash #21). The real entry overwrites
	// the marker below; non-cacheable paths delete it.
	reserveInflight(ctx, rdb, cacheKey, reqBodyHash)

	nextErr := c.Next()
	if nextErr != nil && !IsResponseWrittenErr(nextErr) {
		// Handler failed before writing a response — clear the reservation so
		// an immediate retry isn't told "in progress" for the marker's TTL.
		rdb.Del(context.Background(), cacheKey)
		return nextErr
	}

	status := c.Response().StatusCode()
	if status >= 500 {
		// 5xx is retryable — never leave the marker stranding the retry.
		rdb.Del(context.Background(), cacheKey)
		return nextErr
	}

	body := append([]byte(nil), c.Response().Body()...)
	ct := string(c.Response().Header.ContentType())

	// BUG-API-238: bypass the cache for mutable error codes (currently
	// just free_tier_recycle_requires_claim). A 402 the user resolves
	// in 30s by clicking claim_url must not get strand-cached against
	// the agent's 24h Idempotency-Key. Success + stable failures still
	// cache as before.
	if !shouldCacheResponse(status, body, ct) {
		// Clear the reservation: a mutable 4xx is meant to be retried once
		// the user resolves it, so the marker must not block that retry.
		rdb.Del(context.Background(), cacheKey)
		slog.Info("idempotency.skip_cache_mutable_error",
			"endpoint", endpoint,
			"status", status,
			"request_id", GetRequestID(c),
		)
		return nextErr
	}

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
		return nextErr
	}

	if serr := rdb.Set(context.Background(), cacheKey, payload, idempotencyTTL).Err(); serr != nil {
		slog.Warn("idempotency.redis_set_failed",
			"error", serr,
			"endpoint", endpoint,
			"request_id", GetRequestID(c),
		)
		metrics.RedisErrors.WithLabelValues("idempotency").Inc()
	}
	return nextErr
}

// idempotencyFingerprint handles the implicit-no-header path. The cache
// key is sha256(scope || "|" || route_pattern || "|" || canonical_body)
// with a 120s TTL. The route pattern is sourced from c.Route().Path so
// "/db/new" and "/cache/new" can't collide on identical bodies.
//
// On a cache hit the middleware sets X-Idempotency-Source: fingerprint
// and X-Idempotent-Replay: true, then replays the cached body verbatim.
// On a miss it sets X-Idempotency-Source: miss, runs the handler, and
// caches non-5xx responses.
//
// Fail-open posture: any Redis error short-circuits to c.Next() with a
// WARN log — never block resource creation because Redis is unavailable.
func idempotencyFingerprint(c *fiber.Ctx, rdb *redis.Client, endpoint, scope string) error {
	routePattern := c.Route().Path
	if routePattern == "" {
		// c.Route() returns the placeholder Fiber assigns when the route
		// hasn't been resolved (shouldn't happen for registered routes,
		// but defensive against tests that wire the middleware before
		// app.Post). Fall back to the raw path so we still namespace.
		routePattern = c.Path()
	}

	canonBody, canonErr := canonicalRequestBody(c)
	if canonErr != nil {
		// Body canonicalisation failed (e.g. unparseable multipart
		// request that the handler will reject anyway). Skip dedup —
		// the handler's input validation is the next line of defence.
		slog.Warn("idempotency.fingerprint_canonicalize_failed",
			"error", canonErr,
			"endpoint", endpoint,
			"request_id", GetRequestID(c),
		)
		c.Set(idempotencySourceHeader, idempotencySourceMiss)
		return c.Next()
	}

	fp := sha256Hex(scope + "|" + routePattern + "|" + canonBody)
	cacheKey := fmt.Sprintf("idem-fp:%s:%s:%s", scope, endpoint, fp)

	ctx := c.Context()
	raw, err := rdb.Get(ctx, cacheKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("idempotency.fingerprint_redis_get_failed",
			"error", err,
			"endpoint", endpoint,
			"request_id", GetRequestID(c),
		)
		metrics.RedisErrors.WithLabelValues("idempotency_fingerprint").Inc()
		c.Set(idempotencySourceHeader, idempotencySourceMiss)
		return c.Next()
	}

	if err == nil {
		var entry idemEntry
		if jerr := json.Unmarshal([]byte(raw), &entry); jerr != nil {
			slog.Warn("idempotency.fingerprint_cache_unmarshal_failed",
				"error", jerr, "endpoint", endpoint)
			// Corrupt — fall through to handler and overwrite below.
		} else if entry.InFlight {
			// A concurrent same-fingerprint request is still running (BugBash
			// #21). Return 409 in_progress rather than double-running the
			// handler. The source header still reports the fingerprint path.
			c.Set(idempotencySourceHeader, idempotencySourceFingerprint)
			return respondIdempotencyInProgress(c)
		} else {
			// Cache HIT on the body-fingerprint fallback path. Same
			// refund semantics as the explicit-key branch: the
			// rate-limit slot RateLimit burned on the way in is
			// returned because we're serving a cached response, not
			// re-running the handler (FINDING API-1, Option C).
			RefundRateLimitCounter(c, rdb)
			c.Set(idempotencySourceHeader, idempotencySourceFingerprint)
			c.Set(idempotencyReplayHeader, "true")
			if entry.ContentType != "" {
				c.Set(fiber.HeaderContentType, entry.ContentType)
			}
			return c.Status(entry.StatusCode).Send(entry.Body)
		}
	}

	// Miss — reserve the key (BugBash #21), run the handler, then cache the
	// response (non-5xx only).
	c.Set(idempotencySourceHeader, idempotencySourceMiss)
	reserveInflight(ctx, rdb, cacheKey, sha256Hex(canonBody))
	nextErr := c.Next()
	if nextErr != nil && !IsResponseWrittenErr(nextErr) {
		rdb.Del(context.Background(), cacheKey)
		return nextErr
	}

	status := c.Response().StatusCode()
	if status >= 500 {
		rdb.Del(context.Background(), cacheKey)
		return nextErr
	}

	body := append([]byte(nil), c.Response().Body()...)
	ct := string(c.Response().Header.ContentType())

	// BUG-API-238: same mutable-error bypass as the explicit-key path.
	// The fingerprint TTL is only 120s but the recycle gate still flips
	// inside that window when a user claims fast — and the fingerprint
	// path is the no-header default, so the silent strand is even more
	// likely here.
	if !shouldCacheResponse(status, body, ct) {
		rdb.Del(context.Background(), cacheKey)
		slog.Info("idempotency.fingerprint_skip_cache_mutable_error",
			"endpoint", endpoint,
			"status", status,
			"request_id", GetRequestID(c),
		)
		return nextErr
	}

	entry := idemEntry{
		StatusCode:  status,
		Body:        body,
		ContentType: ct,
		// BodyHash is unused on the fingerprint path (the cache key
		// already encodes the body) but populated for shape parity with
		// the explicit-key entry — keeps debugging tools happy.
		BodyHash: sha256Hex(canonBody),
	}
	payload, jerr := json.Marshal(entry)
	if jerr != nil {
		slog.Warn("idempotency.fingerprint_marshal_failed",
			"error", jerr, "endpoint", endpoint)
		return nextErr
	}

	if serr := rdb.Set(context.Background(), cacheKey, payload, idempotencyFingerprintTTL).Err(); serr != nil {
		slog.Warn("idempotency.fingerprint_redis_set_failed",
			"error", serr,
			"endpoint", endpoint,
			"request_id", GetRequestID(c),
		)
		metrics.RedisErrors.WithLabelValues("idempotency_fingerprint").Inc()
	}
	return nextErr
}

// canonicalRequestBody returns a deterministic byte-stable representation
// of the request body suitable for hashing. Three input shapes are
// handled:
//
//   - application/json: parse, re-encode with sorted keys recursively.
//     {"a":1,"b":2} and {"b":2,"a":1} produce the same canonical form.
//   - multipart/form-data: hash sha256(tarball-bytes) || sorted-form-fields.
//     The full multipart blob carries non-deterministic boundary strings
//     so we can't hash it verbatim — the deterministic parts are the file
//     content (typically a build tarball) and the form fields (env vars,
//     name, etc.).
//   - anything else (raw bytes, text/plain, etc.): hash the raw body.
//
// Empty bodies return "" — two empty POSTs with the same scope + route
// must dedup, which is the correct behaviour for endpoints like
// /webhook/new that accept empty bodies.
func canonicalRequestBody(c *fiber.Ctx) (string, error) {
	ct := strings.ToLower(string(c.Request().Header.ContentType()))

	// Multipart: parse and emit a stable hash of the file contents plus
	// the sorted form-value pairs. Used by /deploy/new (tarball + env).
	if strings.HasPrefix(ct, "multipart/form-data") {
		return canonicalMultipartBody(c)
	}

	body := c.Body()
	if len(body) == 0 {
		return "", nil
	}

	// JSON: re-encode with sorted keys so {"a":1,"b":2} ≡ {"b":2,"a":1}.
	// Anything that isn't valid JSON falls back to the raw-bytes path so
	// a malformed payload still produces a stable fingerprint.
	if strings.HasPrefix(ct, "application/json") || looksLikeJSON(body) {
		var v interface{}
		dec := json.NewDecoder(bytes.NewReader(body))
		if err := dec.Decode(&v); err == nil {
			canon, cerr := canonicalJSON(v)
			if cerr == nil {
				return canon, nil
			}
		}
		// Fall through to raw-bytes fingerprint on parse failure.
	}

	return string(body), nil
}

// canonicalMultipartBody emits a stable digest of a multipart request:
//
//	sha256(file1.name || file1.size || file1.sha256(content))
//	  || sorted(field=value) pairs
//
// The multipart boundary is excluded (it's randomly generated per
// request), as is the field ordering (the spec doesn't fix it). Two
// requests that upload the same tarball with the same form fields in any
// order produce the same canonical string.
func canonicalMultipartBody(c *fiber.Ctx) (string, error) {
	form, err := c.MultipartForm()
	if err != nil {
		return "", err
	}

	var parts []string

	// Files: sorted by field name, each entry is "name:filename:size:sha256(content)".
	fieldNames := make([]string, 0, len(form.File))
	for name := range form.File {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)
	for _, name := range fieldNames {
		for _, fh := range form.File[name] {
			f, oerr := fh.Open()
			if oerr != nil {
				return "", oerr
			}
			h := sha256.New()
			if _, cerr := io.Copy(h, f); cerr != nil {
				_ = f.Close() // read-only fingerprint hash; close error irrelevant
				return "", cerr
			}
			_ = f.Close() // read-only fingerprint hash; close error irrelevant
			parts = append(parts, fmt.Sprintf("file:%s:%s:%d:%x",
				name, fh.Filename, fh.Size, h.Sum(nil)))
		}
	}

	// Form values: sorted by field name. Multi-value fields are joined
	// by NUL bytes after a per-field sort so duplicate sends with the
	// same value-set produce the same fingerprint.
	valueNames := make([]string, 0, len(form.Value))
	for name := range form.Value {
		valueNames = append(valueNames, name)
	}
	sort.Strings(valueNames)
	for _, name := range valueNames {
		vs := append([]string(nil), form.Value[name]...)
		sort.Strings(vs)
		parts = append(parts, fmt.Sprintf("field:%s=%s", name, strings.Join(vs, "\x00")))
	}

	return strings.Join(parts, "|"), nil
}

// canonicalJSON returns a canonical-form encoding of v with map keys
// sorted recursively. Used by canonicalRequestBody so two semantically
// identical JSON bodies that differ only in key order produce the same
// fingerprint.
func canonicalJSON(v interface{}) (string, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeCanonicalJSON is the recursive worker for canonicalJSON. Maps are
// emitted with sorted keys; arrays preserve order (which is semantic in
// JSON); primitives delegate to encoding/json for the same string shape
// the rest of the codebase produces.
func writeCanonicalJSON(buf *bytes.Buffer, v interface{}) error {
	switch t := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// looksLikeJSON is a cheap sniff for bodies that omit a Content-Type
// header but carry a JSON payload (curl --data-raw without -H is a
// frequent agent pattern).
func looksLikeJSON(b []byte) bool {
	for _, c := range b {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		return c == '{' || c == '['
	}
	return false
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
