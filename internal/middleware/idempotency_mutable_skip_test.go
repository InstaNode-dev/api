package middleware_test

// idempotency_mutable_skip_test.go — behavioural coverage for the
// BUG-API-238 cache-skip wires in both idempotency cache-write paths
// (explicit-key 24h and fingerprint-fallback 120s). The static-source
// assertions in idempotency_mutable_cache_test.go cover the registry
// invariants; this file proves the wires actually fire end-to-end.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// newRecycleGateLikeApp builds a Fiber app whose handler emits a 402
// with the canonical free_tier_recycle_requires_claim envelope. Each
// call hits the live handler (no caching), so a behavioural assertion
// can confirm shouldCacheResponse() refused to cache.
func newRecycleGateLikeApp(t *testing.T, endpoint string) (*fiber.App, func()) {
	t.Helper()
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	app.Post("/recycle", middleware.Idempotency(rdb, endpoint), func(c *fiber.Ctx) error {
		// Mirrors the live recycle-gate envelope shape — the fields the
		// shouldCacheResponse helper inspects are `error` and (indirectly)
		// content-type. Body shape kept compact; the cache decision turns
		// on the error string alone.
		return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
			"ok":      false,
			"error":   "free_tier_recycle_requires_claim",
			"message": "claim required",
		})
	})
	return app, cleanup
}

// TestIdempotency_ExplicitKey_RecycleGate402NotCached drives the
// explicit-key path: two POSTs with the same Idempotency-Key both reach
// the handler because the 402 free_tier_recycle_requires_claim must
// never be cached (BUG-API-238). The absence of X-Idempotent-Replay on
// the second call is the wire signal that the cache was skipped.
func TestIdempotency_ExplicitKey_RecycleGate402NotCached(t *testing.T) {
	app, clean := newRecycleGateLikeApp(t, "test.recycle.explicit")
	defer clean()

	ip := uniqueTestIP("recycle-explicit")
	key := "bug238-" + ip

	// Call 1: explicit key, hits the handler.
	resp1 := postWithIdem(t, app, "/recycle", ip, key, `{"x":1}`)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp1.StatusCode)
	assert.Empty(t, resp1.Header.Get("X-Idempotent-Replay"),
		"first call cannot be a replay")
	assert.Equal(t, "explicit", resp1.Header.Get("X-Idempotency-Source"))

	// Call 2: SAME key, SAME body. Pre-fix this replayed the 402 with
	// X-Idempotent-Replay: true. Post-fix the cache write was skipped,
	// so call 2 must reach the handler again (no replay header).
	resp2 := postWithIdem(t, app, "/recycle", ip, key, `{"x":1}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp2.StatusCode,
		"second call should still return 402 (handler ran again)")
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"BUG-API-238: 402 free_tier_recycle_requires_claim MUST NOT be cached — second call must not carry X-Idempotent-Replay")
	body2 := readBody(t, resp2)
	assert.Contains(t, body2, `"free_tier_recycle_requires_claim"`)
	// The presence of the error keyword on a fresh response (not a
	// replay) is the BUG-API-238 contract.
}

// TestIdempotency_Fingerprint_RecycleGate402NotCached drives the
// header-less (fingerprint-fallback) path. Same invariant: the 402 is
// not cached, so the second identical no-header POST hits the handler
// again rather than replaying from the fingerprint cache.
func TestIdempotency_Fingerprint_RecycleGate402NotCached(t *testing.T) {
	app, clean := newRecycleGateLikeApp(t, "test.recycle.fp")
	defer clean()

	ip := uniqueTestIP("recycle-fp")

	resp1 := postWithIdem(t, app, "/recycle", ip, "", `{"x":1}`)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp1.StatusCode)
	assert.Equal(t, "miss", resp1.Header.Get("X-Idempotency-Source"))

	resp2 := postWithIdem(t, app, "/recycle", ip, "", `{"x":1}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp2.StatusCode)
	assert.Empty(t, resp2.Header.Get("X-Idempotent-Replay"),
		"BUG-API-238: fingerprint cache must also skip the recycle-gate 402")
	assert.Equal(t, "miss", resp2.Header.Get("X-Idempotency-Source"),
		"BUG-API-238: second call must be a miss (handler ran), not a fingerprint replay")
}

// TestIdempotency_ExplicitKey_StableErrorStillCached is the negative
// control: a 402 with error="quota_exceeded" (a STABLE error code not in
// mutableErrorCodes) MUST still cache. Without this contrast a future
// regression that bypasses caching for ALL 4xx would silently break the
// Stripe-shape replay contract for legitimate cases.
func TestIdempotency_ExplicitKey_StableErrorStillCached(t *testing.T) {
	rdb, cleanup := testhelpers.SetupTestRedis(t)
	defer cleanup()
	app := fiber.New()
	app.Use(middleware.Fingerprint())
	stableCalls := 0
	app.Post("/stable402", middleware.Idempotency(rdb, "test.stable402"), func(c *fiber.Ctx) error {
		stableCalls++
		return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
			"ok":    false,
			"error": "quota_exceeded",
		})
	})

	ip := uniqueTestIP("stable-402")
	key := "stable-" + ip

	resp1 := postWithIdem(t, app, "/stable402", ip, key, `{"y":1}`)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp1.StatusCode)

	resp2 := postWithIdem(t, app, "/stable402", ip, key, `{"y":1}`)
	defer resp2.Body.Close()
	require.Equal(t, http.StatusPaymentRequired, resp2.StatusCode)
	assert.Equal(t, "true", resp2.Header.Get("X-Idempotent-Replay"),
		"stable 402 (quota_exceeded) MUST still be cached — only mutableErrorCodes entries are skipped")
	assert.Equal(t, 1, stableCalls,
		"stable 402 replay must NOT re-run the handler — Stripe-shape contract")
}

// silence unused-import linter when only context.Background() is used
// transitively.
var _ = context.Background
var _ = strings.TrimSpace
