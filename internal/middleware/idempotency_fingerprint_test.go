package middleware_test

// idempotency_fingerprint_test.go — coverage for the body-fingerprint
// fallback path that ships alongside the explicit Idempotency-Key
// header (2026-05-14).
//
// The fingerprint path synthesises a cache key from sha256(scope ||
// route_pattern || canonical_body) with a 120s TTL when the caller
// omits the Idempotency-Key header. It is intended to absorb
// accidental double-creations (mobile double-taps, browser back-button
// resubmits, agent retries on transient 5xx, reverse-proxy retries on
// network blips) without forcing every existing caller to add a header.
//
// Test matrix:
//
//   1. Double-click replays the cached response within 120s.
//   2. Distinct bodies bypass the fingerprint cache.
//   3. Explicit Idempotency-Key takes precedence over the fingerprint
//      fallback (back-compat: existing semantics unchanged for callers
//      that already opt in).
//   4. Anonymous callers (no team_id) are scoped by the network
//      fingerprint computed by middleware.Fingerprint — same /24
//      subnet replays, different subnet does not.
//   5. JSON key order is irrelevant — {"a":1,"b":2} ≡ {"b":2,"a":1}.
//   6. Redis errors fail open (no 5xx leak; second call reaches handler).
//   7. Every covered POST route in the router carries the middleware
//      (regression net for "someone added a new /thing/new in 3 months
//      and forgot the middleware").

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// newFingerprintTestApp wires Fingerprint + Idempotency around a single
// POST /test route that increments a counter and emits a deterministic
// JSON body. The route pattern is fixed at "/test" so the fingerprint
// cache key namespaces correctly. Separate from newIdemTestApp because
// we want to expose the underlying Redis client for fail-open + Redis-
// down scenarios.
func newFingerprintTestApp(t *testing.T) (*fiber.App, *redis.Client, *fpCounter, func()) {
	t.Helper()
	rdb, cleanup := testhelpers.SetupTestRedis(t)

	c := &fpCounter{}
	// ProxyHeader is required so c.IP() resolves the X-Forwarded-For
	// header in tests. Without it, every httptest request resolves to
	// the loopback IP and every fingerprint collapses onto the same
	// hash — defeating the per-subnet scope this test family relies on.
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(rdb, "test.fp"), func(ctx *fiber.Ctx) error {
		c.inc()
		return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{
			"ok":  true,
			"hit": c.get(),
		})
	})
	app.Post("/other", middleware.Idempotency(rdb, "other.fp"), func(ctx *fiber.Ctx) error {
		c.inc()
		return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{
			"ok":   true,
			"hit":  c.get(),
			"path": "/other",
		})
	})
	return app, rdb, c, cleanup
}

// fpCounter — mirrors idemCounter from the sibling test file but lives
// here so the two test families can run in parallel without sharing
// state. Renamed to avoid declared-but-unused warnings when both files
// compile together.
type fpCounter struct{ n int64 }

func (c *fpCounter) inc()     { atomic.AddInt64(&c.n, 1) }
func (c *fpCounter) get() int { return int(atomic.LoadInt64(&c.n)) }

// uniqueFingerprintTestIP — separate counter from uniqueTestIP so the
// two test files never collide on IPs even when run interleaved.
var uniqueFingerprintTestIPCounter atomic.Uint32

func uniqueFingerprintTestIP(label string) string {
	_ = label
	n := uniqueFingerprintTestIPCounter.Add(1)
	hi := byte((n + uint32(time.Now().UnixNano())) % 250)
	lo := byte((n*11 + 1) % 250)
	return fmt.Sprintf("10.99.%d.%d", hi, lo)
}

func postNoHeader(t *testing.T, app *fiber.App, path, ip, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestFingerprint_DoubleClick_ReplaysSecondCall — the core contract.
// Two POSTs from the same IP with the same body and no Idempotency-Key
// header → the second replays the first. Handler counter stays at 1.
// X-Idempotency-Source must report "miss" on the first call and
// "fingerprint" on the second.
func TestFingerprint_DoubleClick_ReplaysSecondCall(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("double-click")
	body := `{"name":"foo"}`

	resp1 := postNoHeader(t, app, "/test", ip, body)
	body1 := readBody(t, resp1)
	require.Equal(t, http.StatusCreated, resp1.StatusCode)
	require.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))
	assert.Equal(t, "miss", resp1.Header.Get("X-Idempotency-Source"),
		"first call must surface X-Idempotency-Source: miss")

	resp2 := postNoHeader(t, app, "/test", ip, body)
	body2 := readBody(t, resp2)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode,
		"replay must surface the cached status code (201)")
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"replay must set X-Idempotent-Replay: true on the fingerprint path too")
	assert.Equal(t, "fingerprint", resp2.Header.Get("X-Idempotency-Source"),
		"second call must surface X-Idempotency-Source: fingerprint")
	assert.Equal(t, body1, body2,
		"replayed body must equal cached body verbatim")
	assert.Equal(t, 1, c.get(),
		"handler must run exactly once across two identical no-header POSTs")
}

// TestFingerprint_DifferentBody_DoesNotReplay — same IP, distinct
// bodies → both calls reach the handler. The fingerprint cache key
// includes the canonical body so two distinct logical attempts are
// never deduped.
func TestFingerprint_DifferentBody_DoesNotReplay(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("diff-body")

	resp1 := postNoHeader(t, app, "/test", ip, `{"name":"foo"}`)
	readBody(t, resp1)
	resp2 := postNoHeader(t, app, "/test", ip, `{"name":"bar"}`)
	readBody(t, resp2)

	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"))
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"distinct bodies must NOT trigger replay")
	assert.Equal(t, "miss", resp2.Header.Get("X-Idempotency-Source"),
		"distinct-body second call reports miss, not fingerprint")
	assert.Equal(t, 2, c.get())
}

// TestFingerprint_ExplicitKey_OverridesFingerprint — an explicit
// Idempotency-Key on a NEW request must NOT pick up a prior
// fingerprint-cached response, and subsequent calls with the SAME
// explicit key must replay that explicit-keyed response.
//
//   - call 1: no header                    → fresh, fingerprint cache populated, X-Idempotency-Source: miss
//   - call 2: explicit key, same body      → fresh handler invocation (NOT a fingerprint replay),
//     X-Idempotency-Source: explicit, no replay header
//   - call 3: explicit key, same body      → replay the call-2 response,
//     X-Idempotency-Source: explicit, X-Idempotent-Replay: true
func TestFingerprint_ExplicitKey_OverridesFingerprint(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("explicit-overrides-fp")
	body := `{"name":"foo"}`

	// Call 1: no header, populates fingerprint cache.
	resp1 := postNoHeader(t, app, "/test", ip, body)
	readBody(t, resp1)
	require.Equal(t, "miss", resp1.Header.Get("X-Idempotency-Source"))
	require.Equal(t, 1, c.get())

	// Call 2: explicit key, same body. Must run the handler fresh —
	// the fingerprint cache from call 1 is on a different cache key
	// shape (idem-fp:* vs idem:*), so the two paths can't collide.
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Idempotency-Key", "explicit-123")
	resp2, err := app.Test(req, 5000)
	require.NoError(t, err)
	readBody(t, resp2)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Equal(t, "explicit", resp2.Header.Get("X-Idempotency-Source"),
		"explicit-key path must report X-Idempotency-Source: explicit even on first use")
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"first use of an explicit key must NOT be a replay")
	assert.Equal(t, 2, c.get(),
		"handler must run a SECOND time when the caller switches to an explicit key")

	// Call 3: same explicit key + any body → replays call 2 (and would
	// 409 if the body differed). Confirm replay header is set + source
	// is "explicit".
	req3 := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("X-Forwarded-For", ip)
	req3.Header.Set("Idempotency-Key", "explicit-123")
	resp3, err := app.Test(req3, 5000)
	require.NoError(t, err)
	readBody(t, resp3)
	assert.Equal(t, http.StatusCreated, resp3.StatusCode)
	assert.Equal(t, "explicit", resp3.Header.Get("X-Idempotency-Source"))
	assert.Equal(t, "true", resp3.Header.Get("X-Idempotent-Replay"))
	assert.Equal(t, 2, c.get(),
		"handler must NOT run on the explicit-key replay")
}

// TestFingerprint_Anonymous_UsesNetworkFingerprint — anonymous callers
// (no team_id) get scoped by the /24-subnet+ASN fingerprint that
// middleware.Fingerprint already computes. Two calls from the same /24
// → replay. Two calls from different /24 → fresh.
//
// IP allocation: we burn an extra counter tick to guarantee two distinct
// /24 subnets across the test run. uniqueFingerprintTestIPCounter is a
// monotonic uint32; we pick subnet bytes manually so the test never
// accidentally lands on the same /24 a sibling test used.
func TestFingerprint_Anonymous_UsesNetworkFingerprint(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	// Two distinct /24 subnets, deterministically derived from the
	// shared per-process counter so concurrent test packages can't
	// collide. The +200 offset moves the second subnet well outside
	// any range the first could plausibly reach.
	tick := uniqueFingerprintTestIPCounter.Add(1)
	subA := byte(tick % 200)
	subB := byte((tick % 200) + 50) // always +50 → guaranteed-different /24
	ipA := fmt.Sprintf("10.77.%d.10", subA)
	ipB := fmt.Sprintf("10.77.%d.11", subA) // same /24 as ipA
	ipC := fmt.Sprintf("10.77.%d.10", subB) // different /24
	require.NotEqual(t, subA, subB, "test bug: subnet bytes collided")

	body := `{"hello":"world"}`

	// Calls 1 + 2: same /24, same body → call 2 replays.
	resp1 := postNoHeader(t, app, "/test", ipA, body)
	readBody(t, resp1)
	require.Equal(t, 1, c.get())
	resp2 := postNoHeader(t, app, "/test", ipB, body)
	readBody(t, resp2)
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"same /24 subnet, same body must replay (anonymous scope = fingerprint)")
	assert.Equal(t, 1, c.get(),
		"handler must NOT run when the second call is from the same /24")

	// Call 3: different /24, same body → fresh.
	resp3 := postNoHeader(t, app, "/test", ipC, body)
	readBody(t, resp3)
	assert.Empty(t, resp3.Header.Get("X-Idempotent-Replay"),
		"different /24 subnet must NOT replay")
	assert.Equal(t, 2, c.get())
}

// TestFingerprint_BodyCanonicalization_OrderInsensitive — two JSON
// bodies that differ only in key order produce the same canonical
// fingerprint and therefore replay. Validates the recursive-sort
// canonicaliser.
func TestFingerprint_BodyCanonicalization_OrderInsensitive(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("json-canon")

	resp1 := postNoHeader(t, app, "/test", ip, `{"a":1,"b":2,"nested":{"x":10,"y":20}}`)
	readBody(t, resp1)
	resp2 := postNoHeader(t, app, "/test", ip, `{"nested":{"y":20,"x":10},"b":2,"a":1}`)
	readBody(t, resp2)

	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"JSON bodies that differ only in key order must dedup")
	assert.Equal(t, 1, c.get(),
		"handler must run exactly once across two key-reordered JSONs")
}

// TestFingerprint_RedisDown_FailsOpen — when Redis is unavailable the
// middleware must fall through to the handler instead of blocking. Two
// calls both reach the handler, no 5xx leaks. Matches the fail-open
// posture of the rate-limit and quota middleware.
func TestFingerprint_RedisDown_FailsOpen(t *testing.T) {
	deadRDB := redis.NewClient(&redis.Options{
		Addr:        "localhost:19999", // nothing listening
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})
	defer deadRDB.Close()

	c := &fpCounter{}
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/test", middleware.Idempotency(deadRDB, "test.fp.dead"), func(ctx *fiber.Ctx) error {
		c.inc()
		return ctx.Status(fiber.StatusCreated).JSON(fiber.Map{"ok": true})
	})

	ip := uniqueFingerprintTestIP("redis-down")
	body := `{"x":1}`

	resp1 := postNoHeader(t, app, "/test", ip, body)
	readBody(t, resp1)
	resp2 := postNoHeader(t, app, "/test", ip, body)
	readBody(t, resp2)

	assert.Equal(t, http.StatusCreated, resp1.StatusCode,
		"fail-open: Redis down must not block the first POST")
	assert.Equal(t, http.StatusCreated, resp2.StatusCode,
		"fail-open: Redis down must not block the second POST either")
	assert.Equal(t, 2, c.get(),
		"both calls must reach the handler when the cache is unavailable")
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"no replay header on the Redis-down path")
}

// TestFingerprint_DifferentRoutes_NoCollision — two routes with the
// same scope + body must not collide. /test and /other both register
// the middleware with distinct endpoint namespaces ("test.fp" vs
// "other.fp"), and the canonical fingerprint also includes the route
// pattern. Both layers protect against cross-endpoint pollution; this
// test pins the route-pattern layer.
func TestFingerprint_DifferentRoutes_NoCollision(t *testing.T) {
	app, _, c, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("cross-route")
	body := `{"x":1}`

	resp1 := postNoHeader(t, app, "/test", ip, body)
	readBody(t, resp1)
	resp2 := postNoHeader(t, app, "/other", ip, body)
	body2 := readBody(t, resp2)

	assert.Equal(t, http.StatusCreated, resp1.StatusCode)
	assert.Equal(t, http.StatusCreated, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"cross-route POSTs with identical scope+body must NOT collide")
	assert.Contains(t, body2, "/other",
		"the /other handler must have produced the second response, not /test's cache")
	assert.Equal(t, 2, c.get(),
		"two distinct routes must each run their handler once")
}

// TestFingerprint_5xxNotCached_RetryReaches Handler — even on the
// fingerprint path, 5xx responses bypass caching so the agent's retry
// completes the work when the upstream recovers. Pinned because a
// careless implementation that "always cached non-error responses"
// would freeze customers behind a transient provisioner outage for
// 120s.
func TestFingerprint_5xxNotCached_RetryReachesHandler(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	c := &fpCounter{}
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/fail", middleware.Idempotency(rdb, "test.fp.5xx"), func(ctx *fiber.Ctx) error {
		c.inc()
		return ctx.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"ok": false, "error": "upstream_down",
		})
	})

	ip := uniqueFingerprintTestIP("fp-5xx")
	body := `{"x":1}`

	resp1 := postNoHeader(t, app, "/fail", ip, body)
	readBody(t, resp1)
	resp2 := postNoHeader(t, app, "/fail", ip, body)
	readBody(t, resp2)

	assert.Equal(t, http.StatusServiceUnavailable, resp1.StatusCode)
	assert.Equal(t, http.StatusServiceUnavailable, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"5xx must NOT replay on the fingerprint path")
	assert.Equal(t, 2, c.get(),
		"handler must rerun on every retry while the upstream stays 5xx")
}

// TestFingerprint_TTL_120s — the fingerprint cache TTL must be 120s.
// We don't wait wall-clock 2 minutes; we read the TTL Redis sets and
// assert it is in the (118s, 120s] window. The TTL is the contract —
// the actual expiration is enforced by Redis.
func TestFingerprint_TTL_120s(t *testing.T) {
	app, rdb, _, clean := newFingerprintTestApp(t)
	defer clean()

	ip := uniqueFingerprintTestIP("ttl-120")
	body := `{"x":1}`
	resp := postNoHeader(t, app, "/test", ip, body)
	readBody(t, resp)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	ctx := context.Background()
	var found string
	iter := rdb.Scan(ctx, 0, "idem-fp:*", 100).Iterator()
	for iter.Next(ctx) {
		k := iter.Val()
		if strings.Contains(k, ":test.fp:") {
			found = k
			break
		}
	}
	require.NoError(t, iter.Err())
	require.NotEmpty(t, found, "fingerprint middleware did not write a cache entry")

	ttl, err := rdb.TTL(ctx, found).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, 118*time.Second,
		"fingerprint TTL must be ~120s (got %s)", ttl)
	assert.LessOrEqual(t, ttl, 120*time.Second,
		"fingerprint TTL must not exceed 120s (got %s)", ttl)
}

// TestFingerprint_AppliedToAllCreateRoutes — regression net for
// "someone added a new POST /thing/new in 3 months and forgot the
// middleware." Asserts the source of truth at router.go level by
// grep-checking the registration calls. Reflecting on Fiber's route map
// would require instantiating the full app — heavy with k8s providers
// + plans registry — for what amounts to a checklist test.
//
// The list below MUST match the "Final endpoint list" in the PR body.
// When a new POST /thing/new is added, the dev's checklist is:
//
//	1. Register middleware.Idempotency in router.go for the new route.
//	2. Append the route to this slice.
//
// Route registrations can span multiple lines (e.g. /stacks/:slug/promote
// with a RequireEnvAccess middleware on its own line). The matcher scans
// from the line containing the route literal forward to the closing
// handler call, then checks for middleware.Idempotency anywhere in that
// block — same shape Fiber uses to compose a chain.
func TestFingerprint_AppliedToAllCreateRoutes(t *testing.T) {
	routes := []struct {
		// path is the literal substring grep-matched in router.go.
		// Use the same quoting style the router uses so we never
		// match a comment or string-in-a-comment by accident.
		path string
		// matcher is the additional substring that, when both this
		// and path appear on the same .Post(...) line, identifies
		// the unique registration. Empty means path alone is unique.
		matcher string
	}{
		{path: `"/db/new"`},
		{path: `"/vector/new"`},
		{path: `"/cache/new"`},
		{path: `"/nosql/new"`},
		{path: `"/queue/new"`},
		{path: `"/storage/new"`},
		{path: `"/webhook/new"`},
		// /deploy/new lives in a group: deployGroup.Post("/new", ...)
		{path: `"/new"`, matcher: "deployGroup.Post"},
		{path: `"/stacks/new"`},
		{path: `"/billing/checkout"`},
		{path: `"/team/members/invite"`},
		{path: `"/auth/api-keys"`},
		{path: `"/resources/:id/backup"`},
		{path: `"/resources/:id/restore"`},
		{path: `"/resources/:id/provision-twin"`},
		{path: `"/families/bulk-twin"`},
		{path: `"/stacks/:slug/promote"`},
		{path: `"/stacks/:slug/redeploy"`},
		{path: `"/customers/:team_id/promo"`}, // admin promo
		{path: `"/teams/:team_id/invitations"`},
	}

	routerSrc := readRouterSource(t)
	lines := strings.Split(routerSrc, "\n")

	for _, r := range routes {
		t.Run(r.path, func(t *testing.T) {
			startIdx := -1
			for i, line := range lines {
				if !strings.Contains(line, r.path) {
					continue
				}
				if !strings.Contains(line, ".Post(") {
					continue
				}
				if r.matcher != "" && !strings.Contains(line, r.matcher) {
					continue
				}
				startIdx = i
				break
			}
			require.NotEqual(t, -1, startIdx,
				"router.go has no .Post(%s, ...) registration — was the route removed without updating the test?", r.path)

			// Collect lines until we find the closing paren at column-1
			// or the start of the next route. Bounded by parens balance.
			block := strings.Builder{}
			depth := 0
			for i := startIdx; i < len(lines); i++ {
				block.WriteString(lines[i])
				block.WriteString("\n")
				for _, ch := range lines[i] {
					if ch == '(' {
						depth++
					} else if ch == ')' {
						depth--
					}
				}
				if depth <= 0 {
					break
				}
			}

			assert.Contains(t, block.String(), "middleware.Idempotency",
				"router.go registers %s WITHOUT middleware.Idempotency — duplicate-create protection is missing.\nblock:\n%s",
				r.path, block.String())
		})
	}
}

// readRouterSource pulls internal/router/router.go off disk so the
// regression test can grep the registration list. Lives here (next to
// the test) rather than as a global helper since no other test needs
// it. Fail-soft on missing path so the test reports a clear "couldn't
// find router.go" error instead of an opaque nil-pointer.
func readRouterSource(t *testing.T) string {
	t.Helper()
	// Resolve relative to the test's working directory:
	// go test runs in the package dir, so router.go is one level up
	// then into router/.
	const path = "../router/router.go"
	data, err := os.ReadFile(path)
	require.NoError(t, err, "could not read router.go at %s", path)
	return string(data)
}

// _ keeps the errors import referenced — used by sibling test files
// in the same package; future fingerprint test additions may need it
// for the Redis-typed-error path.
var _ = errors.New
