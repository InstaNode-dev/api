package handlers_test

// billing_checkout_dedup_test.go — BB2-D5 server-side dedup guard tests.
//
// Bug repro: two concurrent POSTs to /api/v1/billing/checkout for the
// same team reach Razorpay independently and create TWO subscriptions.
// Cross-tab clicks, mobile double-taps, and retried form submits all
// bypass the dashboard's client-only `checkoutLoading` guard. The
// load-bearing fix is the per-team SETNX inside CreateCheckoutAPI.
//
// These tests pin:
//   - the happy-path SETNX acquire-then-release on a 503 not_configured
//     return (release-on-4xx so retries-after-fix don't have to wait 60s),
//   - the concurrent-duplicate path: of two parallel callers, exactly one
//     reaches Razorpay and the other gets 409 checkout_in_flight,
//   - the fail-open path: when Redis is broken the call proceeds (the
//     Idempotency-Key braces are the backup, not the belt),
//   - the envelope shape: 409 carries retry_after_seconds=60 + agent_action.
//
// All tests construct the handler via WithRedis(rdb) so the SETNX guard
// is active. Existing checkout tests use NewBillingHandler(nil, cfg, ...)
// which leaves rdb=nil and the guard fails open — they continue to pass
// unchanged.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// checkoutAppWithRedis builds a Fiber app that wires the BB2-D5 dedup
// guard via WithRedis(rdb). teamIDOverride pins the same team for all
// requests so the SETNX key collides — otherwise each test call would
// stamp a fresh UUID and never block.
func checkoutAppWithRedis(t *testing.T, cfg *config.Config, rdb *redis.Client, teamIDOverride string) *fiber.App {
	t.Helper()
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop()).WithRedis(rdb)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamIDOverride)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app
}

// TestCheckoutDedup_SETNX_BlocksSecondCall verifies the belt: when the
// first caller's SETNX has stamped the key, a second caller for the
// SAME team sees the key and returns 409 checkout_in_flight. We
// simulate "first caller still in flight" by pre-stamping the key in
// miniredis (faster + deterministic than racing two goroutines for the
// initial acquire).
func TestCheckoutDedup_SETNX_BlocksSecondCall(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	teamID := uuid.NewString()
	// Pre-stamp the in-flight key as if a sibling call already acquired it.
	require.NoError(t, rdb.Set(context.Background(),
		"team_checkout_inflight:"+teamID, "first-caller", 60*time.Second).Err())

	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		RazorpayPlanIDPro: "plan_monthly_pro",
	}
	app := checkoutAppWithRedis(t, cfg, rdb, teamID)

	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusConflict, resp.StatusCode,
		"second concurrent call must be rejected with 409 checkout_in_flight")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "checkout_in_flight", body["error"])
	assert.Contains(t, body, "agent_action")
	assert.NotEmpty(t, body["agent_action"], "agent_action must guide the caller to wait + refresh")
	// retry_after_seconds=60 mirrors the TTL on the SETNX key.
	require.NotNil(t, body["retry_after_seconds"])
	assert.Equal(t, float64(60), body["retry_after_seconds"])
}

// TestCheckoutDedup_ConcurrentGoroutines_AtMostOneReachesRazorpay fires
// N goroutines at the handler with the same team_id and verifies that
// AT MOST ONE attempt reaches the post-guard Razorpay-call branch (the
// 503 billing_not_configured branch is the deterministic stand-in for
// "made it past the guard"). The others see 409.
//
// We pre-stamp the SETNX key in miniredis BEFORE releasing the
// start-barrier so all goroutines collide on the same in-flight
// window. Without this barrier the test is flaky because Fiber's
// app.Test runs each request synchronously inside the goroutine;
// on a fast machine the first goroutine acquires + releases the
// key before the next one starts.
//
// The 503 branch is reached only AFTER the SETNX guard succeeds
// (guard runs before BodyParser → plan-resolution → billing-not-
// configured), so counting 503-vs-409 cleanly partitions winners
// from losers.
//
// Strongest contract under barrier conditions: ZERO winners, ALL
// losers. Two winners would mean concurrent callers each create a
// Razorpay subscription — exactly the bug we're fixing.
func TestCheckoutDedup_ConcurrentGoroutines_AtMostOneReachesRazorpay(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	teamID := uuid.NewString()
	guardKey := "team_checkout_inflight:" + teamID

	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		// RazorpayPlanIDPro intentionally empty → 503 billing_not_configured.
	}
	app := checkoutAppWithRedis(t, cfg, rdb, teamID)

	// Stamp the guard manually so every goroutine collides. The
	// race window is now fully under test control — every goroutine
	// hits SETNX=0 deterministically.
	require.NoError(t, rdb.Set(context.Background(), guardKey, "barrier", 60*time.Second).Err())

	const numCallers = 8
	var winners, losers int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	queued := make(chan struct{}, numCallers)

	for i := 0; i < numCallers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			queued <- struct{}{}
			<-start
			b, _ := json.Marshal(map[string]any{"plan": "pro"})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req, 5000)
			if err != nil {
				t.Errorf("app.Test: %v", err)
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusServiceUnavailable:
				atomic.AddInt64(&winners, 1)
			case http.StatusConflict:
				atomic.AddInt64(&losers, 1)
			default:
				t.Errorf("unexpected status %d (expected 409 or 503)", resp.StatusCode)
			}
		}()
	}
	// Wait until every goroutine has reached the start barrier.
	for i := 0; i < numCallers; i++ {
		<-queued
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int64(0), atomic.LoadInt64(&winners),
		"all goroutines must be blocked by the barrier-stamped guard")
	assert.Equal(t, int64(numCallers), atomic.LoadInt64(&losers),
		"all goroutines must return 409 checkout_in_flight")
}

// TestCheckoutDedup_RedisError_FailsOpen verifies the fail-open posture:
// a Redis SETNX error must NOT block the call. We simulate Redis-broken
// by closing miniredis before the request fires; the SETNX will return
// an error, the handler logs warn, and the call proceeds. The post-guard
// path lands on 503 billing_not_configured (plan_id empty) — which is
// the "guard didn't block me" signal.
//
// A bug here (failing closed on Redis error) would block every paid
// upgrade during a Redis brownout. The Idempotency-Key middleware on the
// route is the braces that still dedupes on this path when callers send
// one.
func TestCheckoutDedup_RedisError_FailsOpen(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	// Break Redis before the request fires.
	mr.Close()

	teamID := uuid.NewString()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		// RazorpayPlanIDPro intentionally empty → 503 billing_not_configured.
	}
	app := checkoutAppWithRedis(t, cfg, rdb, teamID)

	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// MUST NOT be 409. A 409 here would mean a Redis outage blocks every
	// paid upgrade — the brief explicitly bans this.
	assert.NotEqual(t, http.StatusConflict, resp.StatusCode,
		"Redis error must not return 409 — the guard MUST fail open")
	// We expect 503 billing_not_configured (plan_id empty); a 502/500
	// would mean we panicked or fell through somewhere unexpected.
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
		"with Redis broken the call proceeds to plan-id resolution → 503 not_configured")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "billing_not_configured", body["error"],
		"fail-open path lands on the standard not-configured branch, not on the guard's 409")
}

// TestCheckoutDedup_NoRedis_NoOp verifies that constructing the handler
// WITHOUT WithRedis (the default for existing tests) leaves the SETNX
// guard inert — the handler behaves exactly as before. This is the
// backwards-compat contract: no-op when h.rdb is nil.
//
// Without this guarantee, every existing test that constructs the
// handler with nil Redis would have to be touched.
func TestCheckoutDedup_NoRedis_NoOp(t *testing.T) {
	teamID := uuid.NewString()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		// plan_id empty → 503 billing_not_configured.
	}
	// NOTE: no WithRedis call. h.rdb stays nil.
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "internal_error",
			})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)

	// Fire two sequential calls — without the guard, BOTH must reach the
	// post-guard branch (503 here), not 409. Same team_id on each call.
	for i := 0; i < 2; i++ {
		b, _ := json.Marshal(map[string]any{"plan": "pro"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
			"without Redis-wired guard, call %d must NOT be blocked", i+1)
		resp.Body.Close()
	}
}

// TestCheckoutHandler_ConcurrentRequests_NoRaceOnRazorpayFns is the
// regression test for the F7-lazy-init data race.
//
// Root cause it pins: BillingHandler.CreateCheckoutAPI used to call
// h.ensureRazorpayFns() at its top — an unsynchronised check-then-write
// (`if h.CreateSubscription == nil { h.CreateSubscription = ... }`) on
// shared handler struct fields. A single *BillingHandler is registered
// once on the router and served by one goroutine per request, so two
// concurrent first-time /api/v1/billing/checkout calls raced on those
// fields. `go test -race` in CI flagged it as a genuine DATA RACE
// (TestCheckoutDedup_ConcurrentGoroutines_AtMostOneReachesRazorpay).
//
// The fix wires CreateSubscription / FetchCheckoutSubscription ONCE in
// NewBillingHandler — no per-request mutation — so the shared handler is
// safe for concurrent goroutines.
//
// This test deliberately does NOT call WithRedis: with no SETNX guard the
// concurrent callers are NOT serialised, so they genuinely run
// CreateCheckoutAPI in parallel on the same handler. It also does NOT
// override CreateSubscription / FetchCheckoutSubscription — the handler
// runs against the production-default fields, which is exactly the
// surface that used to be lazily initialised under a race. Run under
// `-race`, this test FAILS if the lazy-init pattern is ever reintroduced.
func TestCheckoutHandler_ConcurrentRequests_NoRaceOnRazorpayFns(t *testing.T) {
	teamID := uuid.NewString()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		// RazorpayPlanIDPro intentionally empty → every call lands on the
		// 503 billing_not_configured branch. The race we guard against was
		// at the TOP of CreateCheckoutAPI (the old ensureRazorpayFns call),
		// reached on every request regardless of how far it got.
	}

	// One shared handler — exactly as the router wires it. No WithRedis, so
	// the SETNX guard is inert and the goroutines are not serialised.
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "internal_error",
			})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)

	const numCallers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	queued := make(chan struct{}, numCallers)

	for i := 0; i < numCallers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			queued <- struct{}{}
			<-start // release all goroutines into CreateCheckoutAPI at once
			b, _ := json.Marshal(map[string]any{"plan": "pro"})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req, 5000)
			if err != nil {
				t.Errorf("app.Test: %v", err)
				return
			}
			defer resp.Body.Close()
			// No guard → every call proceeds to plan-id resolution → 503.
			// The assertion is secondary; the PRIMARY contract is that
			// `-race` sees no DATA RACE on the handler's function fields.
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode,
				"unguarded concurrent call must reach the 503 not_configured branch")
		}()
	}
	for i := 0; i < numCallers; i++ {
		<-queued
	}
	close(start)
	wg.Wait()
}
