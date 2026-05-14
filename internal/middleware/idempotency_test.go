package middleware_test

// idempotency_test.go — coverage for the Idempotency-Key middleware.
// Drives every contract axis from the spec through a minimal Fiber app
// backed by the test Redis instance:
//
//   1. Missing key       → backwards-compat (no caching, no replay header)
//   2. Replay same body  → 200 + cached body + X-Idempotent-Replay: true
//   3. Replay diff body  → 409 idempotency_key_conflict
//   4. Different key     → fresh response (no replay)
//   5. Invalid key       → 400 invalid_idempotency_key (too long, non-ASCII)
//   6. 5xx never cached  → retry produces fresh attempt
//   7. TTL expiration    → after 24h the cache entry is gone
//
// The fingerprint scope is exercised via the X-Forwarded-For header that
// the Fingerprint middleware reads — every test uses a unique IP so the
// per-fingerprint scope isolates concurrent tests on the same Redis db.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// idemCounter counts how many times the underlying handler ran. The test
// asserts on the COUNT — a replay must NOT increment it; a different
// request body MUST.
type idemCounter struct{ n int64 }

func (c *idemCounter) inc()     { atomic.AddInt64(&c.n, 1) }
func (c *idemCounter) get() int { return int(atomic.LoadInt64(&c.n)) }

// newIdemTestApp builds a Fiber app with Fingerprint + Idempotency
// installed and a single POST /test route that increments a counter and
// returns 201 with a deterministic JSON body. The body includes the
// counter value so a replay-vs-fresh assertion can compare bytes.
func newIdemTestApp(t *testing.T, counter *idemCounter) (*fiber.App, func()) {
	t.Helper()
	rdb, cleanup := testhelpers.SetupTestRedis(t)

	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.endpoint"), func(c *fiber.Ctx) error {
		counter.inc()
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"ok":  true,
			"hit": counter.get(),
		})
	})
	// Endpoint that always returns 5xx so we can test "never cache" behaviour.
	app.Post("/test-5xx", middleware.Idempotency(rdb, "test.fivexx"), func(c *fiber.Ctx) error {
		counter.inc()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"ok":  false,
			"hit": counter.get(),
		})
	})
	return app, cleanup
}

// postWithIdem sends a POST to path with the given body and optional
// Idempotency-Key header. ip is mapped onto X-Forwarded-For so the
// Fingerprint middleware computes a scope per test.
func postWithIdem(t *testing.T, app *fiber.App, path, ip, idemKey, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// readBody drains and returns the response body as a string. Always called
// once per response — Fiber's test transport closes the body for us but
// the io.ReadAll guards against partial reads.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}

// TestIdempotency_MissingKey_FirstCallIsFresh — when no Idempotency-Key
// header is sent the first call runs the handler (X-Idempotency-Source:
// miss). The second call IS deduped by the body-fingerprint fallback
// (see TestFingerprint_DoubleClick_ReplaysSecondCall) — so we only assert
// the first-call shape here, leaving the replay shape to the dedicated
// fingerprint tests.
//
// Pre-fingerprint contract (retired 2026-05-14): two identical
// no-header POSTs both reached the handler. That created the bug the
// fingerprint fallback fixes — agents retrying on transient 5xx, mobile
// double-taps, and reverse-proxy network-blip retries all created
// duplicate resources. This test no longer asserts that retired contract.
func TestIdempotency_MissingKey_FirstCallIsFresh(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("missing-key")
	resp1 := postWithIdem(t, app, "/test", ip, "", `{"x":1}`)
	defer resp1.Body.Close()

	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"),
		"first call must NOT be marked as a replay even with the new fallback")
	assert.Equal(t, "miss", resp1.Header.Get("X-Idempotency-Source"),
		"first call without a header reports X-Idempotency-Source: miss")
	assert.Equal(t, 1, c.get(), "handler must run on the first call")
	readBody(t, resp1)
}

// TestIdempotency_ReplaySameBody_CachedResponse — the core replay flow.
// First call hits the handler and returns 201; second call with same key
// + same body returns the EXACT cached body verbatim + 201 +
// X-Idempotent-Replay: true. The handler counter MUST stay at 1.
func TestIdempotency_ReplaySameBody_CachedResponse(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("replay-same")
	key := "test-key-" + ip
	body := `{"x":1}`

	resp1 := postWithIdem(t, app, "/test", ip, key, body)
	body1 := readBody(t, resp1)
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"),
		"first call must NOT be marked as a replay")

	resp2 := postWithIdem(t, app, "/test", ip, key, body)
	body2 := readBody(t, resp2)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode,
		"replay must surface the cached status code (201)")
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"replay must set X-Idempotent-Replay: true")
	assert.Equal(t, body1, body2,
		"replayed body must equal cached body verbatim")
	assert.Equal(t, 1, c.get(),
		"handler must run exactly once across two calls with the same key+body")
}

// TestIdempotency_ReplayDifferentBody_Returns409 — agents reusing a key
// for a logically different request is almost certainly a bug. Return
// 409 with a structured error so the agent can branch on it. The handler
// must NOT run on the second call (the cached entry detects the
// mismatch before we forward).
func TestIdempotency_ReplayDifferentBody_Returns409(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("replay-diff")
	key := "test-key-" + ip

	resp1 := postWithIdem(t, app, "/test", ip, key, `{"x":1}`)
	readBody(t, resp1)
	assert.Equal(t, http.StatusCreated, resp1.StatusCode)

	resp2 := postWithIdem(t, app, "/test", ip, key, `{"x":2}`)
	body2 := readBody(t, resp2)
	assert.Equal(t, http.StatusConflict, resp2.StatusCode,
		"same key with different body must return 409")
	assert.Contains(t, body2, "idempotency_key_conflict",
		"conflict body must carry the structured error keyword")
	assert.Equal(t, 1, c.get(),
		"handler must NOT run on the conflict path (replay must short-circuit)")
}

// TestIdempotency_DifferentKey_FreshResponse — two distinct keys MUST
// produce two handler invocations even when the body is identical. The
// "no key" guardrail and the "key uniqueness" guardrail together cover
// the full agent-retry matrix.
func TestIdempotency_DifferentKey_FreshResponse(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("diff-key")
	body := `{"x":1}`

	resp1 := postWithIdem(t, app, "/test", ip, "key-A", body)
	readBody(t, resp1)
	resp2 := postWithIdem(t, app, "/test", ip, "key-B", body)
	readBody(t, resp2)

	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"different keys must NOT trigger replay")
	assert.Equal(t, 2, c.get())
}

// TestIdempotency_InvalidKey_TooLong_Returns400 — keys >255 chars are
// rejected with 400 (not silently ignored). Silent-ignore would let a
// buggy agent think the key took effect when it didn't.
func TestIdempotency_InvalidKey_TooLong_Returns400(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("too-long")
	tooLong := strings.Repeat("k", 256)
	resp := postWithIdem(t, app, "/test", ip, tooLong, `{"x":1}`)
	body := readBody(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, body, "invalid_idempotency_key")
	assert.Equal(t, 0, c.get(),
		"handler must NOT run when the key is invalid")
}

// TestIdempotency_InvalidKey_NonASCII_Returns400 — only ASCII printable
// characters are accepted (0x20-0x7E). A unicode character must reject.
func TestIdempotency_InvalidKey_NonASCII_Returns400(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("non-ascii")
	// "café" has a non-ASCII é.
	resp := postWithIdem(t, app, "/test", ip, "café", `{"x":1}`)
	body := readBody(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, body, "invalid_idempotency_key")
	assert.Equal(t, 0, c.get())
}

// TestIdempotency_5xxNotCached_RetryIsFresh — 5xx responses (transient
// server errors) MUST NOT be cached: the whole point of an
// Idempotency-Key is that the agent's retry can complete the work. If
// we cached a 500 it would replay forever, making the bug worse. The
// handler must run again on the second call with the same key + body.
func TestIdempotency_5xxNotCached_RetryIsFresh(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("not-cached")
	key := "test-key-" + ip

	resp1 := postWithIdem(t, app, "/test-5xx", ip, key, `{"x":1}`)
	readBody(t, resp1)
	resp2 := postWithIdem(t, app, "/test-5xx", ip, key, `{"x":1}`)
	readBody(t, resp2)

	assert.Equal(t, http.StatusInternalServerError, resp1.StatusCode)
	assert.Equal(t, http.StatusInternalServerError, resp2.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"5xx must NOT replay — the agent's retry must reach the handler")
	assert.Equal(t, 2, c.get(),
		"handler must run on every retry while the upstream stays 5xx")
}

// TestIdempotency_TTLExpiration_24h — entries auto-expire after 24h. We
// don't wait wall-clock 24h; instead we read the TTL Redis sets on the
// key and assert it is in the (23h, 24h] window. The TTL is the
// contract — the actual expiration is enforced by Redis.
func TestIdempotency_TTLExpiration_24h(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	c := &idemCounter{}
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.ttl"), func(ctx *fiber.Ctx) error {
		c.inc()
		return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{"ok": true})
	})

	ip := uniqueTestIP("ttl")
	key := "test-key-ttl-" + ip

	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", key)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Find the cached key in Redis and read its TTL. The key shape is
	// idem:<scope>:<endpoint>:<sha256(key)> — we scan rather than
	// recompute the scope/hash so this test stays decoupled from the
	// internal key encoding.
	ctx := context.Background()
	var found string
	iter := rdb.Scan(ctx, 0, "idem:*", 100).Iterator()
	for iter.Next(ctx) {
		k := iter.Val()
		if strings.Contains(k, ":test.ttl:") {
			found = k
			break
		}
	}
	require.NoError(t, iter.Err())
	require.NotEmpty(t, found, "Idempotency middleware did not write a cache entry")

	ttl, err := rdb.TTL(ctx, found).Result()
	require.NoError(t, err)
	// Allow a generous window: TTL was set at 24h, this test runs in
	// milliseconds. Anything less than 23h would indicate a wiring bug
	// (e.g. 24-second TTL instead of 24-hour).
	assert.Greater(t, ttl, 23*time.Hour,
		"TTL must be in the (23h, 24h] window — got %s", ttl)
	assert.LessOrEqual(t, ttl, 24*time.Hour,
		"TTL must not exceed 24h — got %s", ttl)
}

// TestIdempotency_4xxIsCached — 4xx responses (e.g. 402 quota_exceeded)
// MUST replay. Otherwise an agent that hit a quota wall would retry-storm
// the wall on every reconnect; the cached 402 lets the upstream agent
// loop see the same error and stop. This is the rationale for the
// "5xx not cached / 4xx cached" rule.
//
// IMPORTANT (BB2-D5, 2026-05-14): this test exercises the REAL production
// error path — handlers.WriteFiberError (which delegates to respondError)
// returns the handlers.ErrResponseWritten sentinel after committing the
// 4xx body to the wire. Pre-BB2-D5 the test used c.Status().JSON() which
// returns nil and bypassed the middleware's bail clause — so the test
// passed for the wrong reason while production silently skipped caching
// every 4xx error a handler produced via respondError. The Fiber
// ErrorHandler mirrors the production short-circuit on ErrResponseWritten.
func TestIdempotency_4xxIsCached(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	hits := &idemCounter{}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Production behaviour: respondError already wrote the body —
			// short-circuit so we don't overwrite. Matches router/router.go.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.fourxx"), func(c *fiber.Ctx) error {
		hits.inc()
		// Real production error path: respondError writes status+body and
		// returns ErrResponseWritten as a sentinel. This is what every
		// handler emits for /db/new, /cache/new, /deploy/new etc.
		return handlers.WriteFiberError(c, fiber.StatusPaymentRequired,
			"quota_exceeded", "Tier cap reached — upgrade or wait for reset.")
	})

	ip := uniqueTestIP("fourxx")
	key := "test-key-fourxx-" + ip

	resp1 := postWithIdem(t, app, "/test", ip, key, `{"x":1}`)
	readBody(t, resp1)
	resp2 := postWithIdem(t, app, "/test", ip, key, `{"x":1}`)
	body2 := readBody(t, resp2)

	assert.Equal(t, http.StatusPaymentRequired, resp1.StatusCode)
	assert.Equal(t, http.StatusPaymentRequired, resp2.StatusCode,
		"4xx replay must surface the original status")
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"))
	assert.Contains(t, body2, "quota_exceeded",
		"replayed body must match the cached one")
	assert.Equal(t, 1, hits.get(),
		"handler must NOT re-run when a cached 4xx is available — BB2-D5 root case")
}

// TestIdempotency_RealHandlerErrorPathCaches — BB2-D5 regression test.
//
// Drives the EXACT production failure: an agent hits /deploy/new over its
// tier cap, the server returns 402 cap-blocked via respondError (which
// writes the body and returns ErrResponseWritten), and the agent retries
// with the same Idempotency-Key. Before BB2-D5 the second call ran the
// handler again — re-billing, re-side-effecting. After the fix the second
// call short-circuits to the cached 402.
//
// This test FAILS before the fix (handler hit count = 2) and PASSES after
// (handler hit count = 1).
func TestIdempotency_RealHandlerErrorPathCaches(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	hits := &idemCounter{}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Use(middleware.Fingerprint())
	app.Post("/deploy/new", middleware.Idempotency(rdb, "deploy.new"),
		func(c *fiber.Ctx) error {
			hits.inc()
			return handlers.WriteFiberError(c, fiber.StatusPaymentRequired,
				"quota_exceeded",
				"deployments_apps cap reached for hobby tier. Upgrade or delete an existing deploy.")
		})

	ip := uniqueTestIP("bb2d5-real-path")
	key := "deploy-retry-key-" + ip
	body := `{"tarball":"redacted","env":"production"}`

	resp1 := postWithIdem(t, app, "/deploy/new", ip, key, body)
	body1 := readBody(t, resp1)
	require.Equal(t, http.StatusPaymentRequired, resp1.StatusCode,
		"first call must surface the 402 from respondError")
	require.Empty(t, resp1.Header.Get("X-Idempotent-Replay"),
		"first call must NOT be marked as a replay")
	require.Contains(t, body1, "quota_exceeded")

	// Agent retries with the same Idempotency-Key. Production behaviour
	// before the fix: handler runs again, side effects repeat. After the
	// fix: cached 402 replays, handler never invoked.
	resp2 := postWithIdem(t, app, "/deploy/new", ip, key, body)
	body2 := readBody(t, resp2)
	assert.Equal(t, http.StatusPaymentRequired, resp2.StatusCode,
		"replay must surface the cached 402")
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"replay header must be set so the agent knows this is a cached error")
	assert.Equal(t, body1, body2,
		"replayed body must equal the original 402 envelope verbatim")
	assert.Equal(t, 1, hits.get(),
		"handler must run EXACTLY ONCE across two identical Idempotency-Key calls — "+
			"this is the BB2-D5 contract that was silently broken in production")
}

// TestIdempotency_5xxFromRespondError_NotCached — guardrail that the BB2-D5
// fix does NOT over-correct. A handler that calls respondError with a 5xx
// status (e.g. provision_failed) still returns ErrResponseWritten, but the
// status >= 500 branch must still bypass caching so retries can complete
// the work once the upstream recovers. Without this guardrail a transient
// provisioner outage would freeze every retry behind a cached 503 for 24h.
func TestIdempotency_5xxFromRespondError_NotCached(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	hits := &idemCounter{}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.fivexx-real"),
		func(c *fiber.Ctx) error {
			hits.inc()
			return handlers.WriteFiberError(c, fiber.StatusServiceUnavailable,
				"provision_failed", "Upstream provisioner unavailable.")
		})

	ip := uniqueTestIP("bb2d5-5xx-real")
	key := "test-key-5xx-real-" + ip
	body := `{"x":1}`

	resp1 := postWithIdem(t, app, "/test", ip, key, body)
	readBody(t, resp1)
	resp2 := postWithIdem(t, app, "/test", ip, key, body)
	readBody(t, resp2)

	assert.Equal(t, http.StatusServiceUnavailable, resp1.StatusCode)
	assert.Equal(t, http.StatusServiceUnavailable, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"5xx must NOT replay even when reached via respondError — "+
			"the agent's retry must reach the handler so the work eventually completes")
	assert.Equal(t, 2, hits.get(),
		"handler must re-run on every retry while the upstream stays 5xx")
}

// TestIdempotency_NonSentinelErrorNotCached — guardrail that a plumbing
// error (e.g. a fiber.NewError returned by deeper middleware, a panic
// recovered by Fiber's default recover) is NOT cached. Only the
// ErrResponseWritten sentinel — which means "I committed a real 4xx/5xx
// body to the wire on purpose" — triggers the cache write. Anything else
// is a bug we don't want to memoise for 24h.
func TestIdempotency_NonSentinelErrorNotCached(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	hits := &idemCounter{}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Default Fiber behaviour: write 500 + plain message.
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.bare-error"),
		func(c *fiber.Ctx) error {
			hits.inc()
			// A bare error — NO body written. Production would hit the
			// Fiber ErrorHandler which writes a 500. Idempotency middleware
			// must NOT cache this — the response body wasn't intentionally
			// shaped by respondError.
			return errors.New("bare plumbing error")
		})

	ip := uniqueTestIP("bb2d5-bare")
	key := "test-bare-" + ip
	body := `{"x":1}`

	resp1 := postWithIdem(t, app, "/test", ip, key, body)
	readBody(t, resp1)
	resp2 := postWithIdem(t, app, "/test", ip, key, body)
	readBody(t, resp2)

	// Both calls fall through Fiber's default 500 handler.
	assert.Equal(t, http.StatusInternalServerError, resp1.StatusCode)
	assert.Equal(t, http.StatusInternalServerError, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"non-sentinel errors must NOT be cached — only ErrResponseWritten triggers caching")
	assert.Equal(t, 2, hits.get(),
		"handler must re-run when the error is a plumbing bug, not an intentional respondError")
}

// TestIdempotency_WhitespaceOnlyKey_BackwardsCompat — Go's net/http
// strips/normalises whitespace-only headers before they reach the app,
// so the practical outcome is "no header" (handler runs normally, no
// caching, no 400). This test pins that observed behaviour so a future
// change to fiber/fasthttp that surfaces whitespace headers is caught
// (in which case the middleware's strings.TrimSpace fallthrough would
// reject them as invalid_idempotency_key — also acceptable).
func TestIdempotency_WhitespaceOnlyKey_BackwardsCompat(t *testing.T) {
	c := &idemCounter{}
	app, clean := newIdemTestApp(t, c)
	defer clean()

	ip := uniqueTestIP("ws-key")
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{"x":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", "   ")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	readBody(t, resp)
	// Either 201 (header stripped → no-op path) or 400 (header surfaced
	// → trimmed-empty → rejected). Both preserve the "no silent
	// idempotency bypass" contract.
	assert.True(t,
		resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusBadRequest,
		"whitespace-only key must either be ignored (201) or rejected (400); got %d",
		resp.StatusCode)
}

// uniqueTestIPCounter scopes IP allocation per-process so concurrent test
// packages don't collide on the same X-Forwarded-For + day. A simple
// atomic counter is enough — the upper bytes vary across calls.
var uniqueTestIPCounter atomic.Uint32

// uniqueTestIP returns an IPv4 in 10.42.X.Y where X.Y is monotonically
// increasing. The label is informational and shows up in test failure
// diagnostics ("[idem-ip:replay-same]").
func uniqueTestIP(label string) string {
	n := uniqueTestIPCounter.Add(1)
	// Mix in nanoseconds to reduce cross-test-run reuse on the same Redis db.
	hi := byte((n + uint32(time.Now().UnixNano())) % 250)
	lo := byte((n * 7) % 250)
	return fmt.Sprintf("10.42.%d.%d", hi, lo) // label unused but kept for callsite readability
}

// ─────────────────────────────────────────────────────────────────────────
// X-RateLimit-* response headers — added in the same PR per persona-1 task #9.
// ─────────────────────────────────────────────────────────────────────────

// newRateLimitTestApp builds a Fiber app with Fingerprint + RateLimit
// installed and a single GET /test route. The Limit is set low (3) so
// tests can drive both the under-limit and over-limit paths without
// burning hundreds of requests.
func newRateLimitTestApp(t *testing.T) (*fiber.App, func()) {
	t.Helper()
	rdb, cleanup := testhelpers.SetupTestRedis(t)

	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{
		Limit:     3,
		KeyPrefix: "rl-test",
	}))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app, cleanup
}

// TestRateLimit_HeadersPresentOnSuccess — every response from a route
// covered by the RateLimit middleware must carry the three X-RateLimit-*
// headers. Agents read these to decide whether to back off. Missing
// headers means the agent has no signal short of the eventual 429.
func TestRateLimit_HeadersPresentOnSuccess(t *testing.T) {
	app, clean := newRateLimitTestApp(t)
	defer clean()

	ip := uniqueTestIP("rl-success")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "3", resp.Header.Get("X-RateLimit-Limit"),
		"X-RateLimit-Limit must reflect the configured cap")
	assert.Equal(t, "2", resp.Header.Get("X-RateLimit-Remaining"),
		"X-RateLimit-Remaining must be cap minus current count (3-1)")
	reset := resp.Header.Get("X-RateLimit-Reset")
	assert.NotEmpty(t, reset, "X-RateLimit-Reset must be set (Unix seconds)")
	// Reset must be a Unix-seconds value in the near future (next midnight).
	now := time.Now().UTC()
	resetT, perr := time.Parse(time.RFC3339, time.Unix(parseInt64(t, reset), 0).UTC().Format(time.RFC3339))
	require.NoError(t, perr)
	assert.True(t, resetT.After(now),
		"X-RateLimit-Reset must be a future Unix timestamp; got %s (now %s)", resetT, now)
	assert.True(t, resetT.Before(now.Add(25*time.Hour)),
		"X-RateLimit-Reset must be within 25h (next UTC midnight); got %s", resetT)
}

// TestRateLimit_RemainingDecrementsAcrossRequests — sequential requests
// from the same fingerprint must observe the remaining counter ticking
// down by exactly 1 per request, matching the global daily counter.
func TestRateLimit_RemainingDecrementsAcrossRequests(t *testing.T) {
	app, clean := newRateLimitTestApp(t)
	defer clean()

	ip := uniqueTestIP("rl-decrement")
	expectRemaining := []string{"2", "1", "0", "0"}
	for i, want := range expectRemaining {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		resp.Body.Close()
		// After the 4th call we're over-limit; remaining floors at 0
		// rather than going negative (sanity from the agent's POV).
		got := resp.Header.Get("X-RateLimit-Remaining")
		assert.Equal(t, want, got,
			"request #%d: remaining must be %s, got %s", i+1, want, got)
	}
}

// TestRateLimit_HeadersOnOverLimitResponse — even when the daily counter
// is past the cap, the headers MUST still surface so the agent sees its
// budget is zero. Without these the over-limit response and the under-
// limit response look identical to the caller until the eventual 429.
func TestRateLimit_HeadersOnOverLimitResponse(t *testing.T) {
	app, clean := newRateLimitTestApp(t)
	defer clean()

	ip := uniqueTestIP("rl-over")
	// Burn through the 3-request cap.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		resp.Body.Close()
	}
	// 4th request: over the cap.
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, "3", resp.Header.Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", resp.Header.Get("X-RateLimit-Remaining"),
		"over-limit Remaining must floor at 0 (never negative)")
	assert.NotEmpty(t, resp.Header.Get("X-RateLimit-Reset"))
}

// parseInt64 — tiny test helper to convert the X-RateLimit-Reset header
// to int64 without depending on strconv inside the assertion.
func parseInt64(t *testing.T, s string) int64 {
	t.Helper()
	var n int64
	_, err := fmt.Sscanf(s, "%d", &n)
	require.NoError(t, err)
	return n
}

// _ keeps the bytes import used (a future test may need raw byte
// assertions on cached payloads); intentionally referenced to avoid
// unused-import churn on the next test addition.
var _ = bytes.NewBuffer
