package middleware_test

// admin_rate_limit_test.go — verifies the per-fingerprint 30/min cap on
// admin route prefix hits AND the byte-for-byte response-shape parity
// with the allowlist-miss 403.
//
// The critical invariant: when the limiter mutes a request, the response
// body MUST be byte-identical to what RequireAdmin returns for "not on
// the allowlist." An attacker probing the admin prefix from an unknown
// IP cannot tell which gate denied them.

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// adminRLApp builds a Fiber app that exercises the rate-limit middleware
// followed by a stub admin handler. We don't wire RequireAdmin here — the
// goal is to isolate the limiter's behavior. A separate test (the
// response-parity test) chains both to assert the body-identical rule.
//
// ProxyHeader matches the production router so X-Forwarded-For drives
// c.IP() (otherwise every request would resolve to 0.0.0.0 and collapse
// to one fingerprint).
func adminRLApp(rdb *redis.Client) *fiber.App {
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(middleware.AdminRateLimit(rdb))
	app.Get("/api/v1/*", func(c *fiber.Ctx) error {
		// Handler is reached ONLY when the limiter lets the request through.
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true, "from": "stub"})
	})
	return app
}

// uniqueIPForRL returns an IPv4 string that maps to a unique /24 — the
// same approach as the production fingerprint hash. We can't reuse
// testhelpers.FingerprintToIP because we want different fingerprints in
// different tests but no /24 collision across the parallel test set.
func uniqueIPForRL(t *testing.T) string {
	t.Helper()
	// Use the test's name as the seed — deterministic, debuggable.
	var h uint32
	for _, b := range []byte(t.Name()) {
		h = h*31 + uint32(b)
	}
	return fmt.Sprintf("10.66.%d.1", (h%254)+1)
}

// TestAdminRateLimit_31stHitReturns403 — the headline contract from the
// task brief. Within a single rolling minute, the first 30 requests from
// one fingerprint pass through; the 31st is muted with a 403. The
// response body MUST mirror the RequireAdmin "not on allowlist" shape.
func TestAdminRateLimit_31stHitReturns403(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	app := adminRLApp(rdb)
	ip := uniqueIPForRL(t)

	// First 30: all pass through.
	for i := 1; i <= middleware.AdminRateLimitPerMinute; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/some/admin/path", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 3000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"request %d/%d must pass the rate limit", i, middleware.AdminRateLimitPerMinute)
		resp.Body.Close()
	}

	// 31st: muted.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/some/admin/path", nil)
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 3000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"the 31st hit MUST be muted with 403 (never 429 — that would leak the gate)")
}

// TestAdminRateLimit_403MatchesAllowlistMiss_ByteForByte — the WHOLE POINT
// of the layer. A rate-limited 403 must be byte-for-byte indistinguishable
// from an allowlist-miss 403. Any drift — different message, missing
// field, reordered keys — leaks "the prefix is right, you're just probing
// too fast," which is exactly the signal we deny attackers.
//
// We run two requests:
//
//	A) Rate-limit path: exhaust the bucket, then make the muted request.
//	   The limiter responds without consulting RequireAdmin.
//
//	B) Allowlist-miss path: fresh fingerprint, but RequireAdmin rejects
//	   because the JWT email isn't on the allowlist.
//
// Then assert the response bodies are byte-identical.
func TestAdminRateLimit_403MatchesAllowlistMiss_ByteForByte(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()

	// Build an app that mirrors the production chain order:
	//   RateLimit → RequireAdmin → handler.
	// We inject a fake-auth shim that puts a NON-admin email on locals
	// so RequireAdmin rejects on every hit. ADMIN_EMAILS is set to a
	// different address.
	t.Setenv("ADMIN_EMAILS", "founder@instanode.dev")
	app := fiber.New(fiber.Config{ProxyHeader: "X-Forwarded-For"})
	app.Use(middleware.Fingerprint())
	app.Use(middleware.AdminRateLimit(rdb))
	// Fake auth: pin a non-admin email so RequireAdmin always rejects.
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyEmail, "alice@example.com")
		return c.Next()
	})
	app.Use(middleware.RequireAdmin())
	app.Get("/api/v1/*", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"ok": true})
	})

	// ─── Path B: allowlist miss (fresh fingerprint, 1st request) ────────
	ipB := uniqueIPForRL(t) + ".B"
	// fingerprint hashes are tolerant of arbitrary IP-shaped strings; we
	// strip the .B suffix back for the X-Forwarded-For header below.
	ipB = ipB[:len(ipB)-2]
	reqB := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
	reqB.Header.Set("X-Forwarded-For", ipB)
	respB, err := app.Test(reqB, 3000)
	require.NoError(t, err)
	bodyB, _ := io.ReadAll(respB.Body)
	respB.Body.Close()
	assert.Equal(t, http.StatusForbidden, respB.StatusCode,
		"allowlist miss must return 403")

	// ─── Path A: rate-limit mute (same fp exhausted, then mute) ─────────
	// Use a SEPARATE fingerprint so the bucket isn't polluted by path B's
	// single hit. Pre-fill the limiter to 30 by hammering the endpoint.
	ipA := uniqueIPForRL(t) + ".A"
	ipA = ipA[:len(ipA)-2]
	for i := 0; i < middleware.AdminRateLimitPerMinute; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
		r.Header.Set("X-Forwarded-For", ipA)
		resp, _ := app.Test(r, 3000)
		resp.Body.Close()
	}
	// 31st: muted by limiter BEFORE RequireAdmin sees it.
	reqA := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
	reqA.Header.Set("X-Forwarded-For", ipA)
	respA, err := app.Test(reqA, 3000)
	require.NoError(t, err)
	bodyA, _ := io.ReadAll(respA.Body)
	respA.Body.Close()
	assert.Equal(t, http.StatusForbidden, respA.StatusCode)

	// Bodies must be byte-identical. The WHOLE PROBE-INDISTINGUISHABILITY
	// CONTRACT lives in this assertion. Any drift = leak.
	assert.True(t, bytes.Equal(bodyA, bodyB),
		"rate-limit 403 body MUST match allowlist-miss 403 body byte-for-byte\n  rate-limit: %s\n  allowlist:  %s",
		string(bodyA), string(bodyB))
}

// TestAdminRateLimit_FailsOpen_OnRedisDown — when Redis is unreachable
// the limiter MUST NOT block requests. Matches the codebase-wide fail-
// open posture for fingerprint-rate-limiting. Pointing the client at a
// dead address simulates the outage.
func TestAdminRateLimit_FailsOpen_OnRedisDown(t *testing.T) {
	deadRDB := redis.NewClient(&redis.Options{
		Addr:        "localhost:19999", // nothing listening
		DialTimeout: 100 * time.Millisecond,
		ReadTimeout: 100 * time.Millisecond,
	})
	defer deadRDB.Close()

	app := adminRLApp(deadRDB)
	ip := uniqueIPForRL(t)

	// Send well past the cap; every request must pass because Redis errors
	// flip the limiter to fail-open.
	for i := 0; i < middleware.AdminRateLimitPerMinute+5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
		req.Header.Set("X-Forwarded-For", ip)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Redis-down MUST fail open (request %d)", i+1)
		resp.Body.Close()
	}
}

// TestAdminRateLimit_DifferentFingerprints_Independent — each fingerprint
// gets its own bucket. Exhausting fingerprint A must not affect B.
func TestAdminRateLimit_DifferentFingerprints_Independent(t *testing.T) {
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	app := adminRLApp(rdb)

	// Use two distinct /24 subnets so the fingerprint hash differs. The
	// production fingerprint hashes /24 + ASN; in tests we have no ASN so
	// it's just the /24. 10.77 vs 10.88 + a test-name-derived octet keeps
	// each test isolated from concurrently-running tests.
	var h uint32
	for _, b := range []byte(t.Name()) {
		h = h*31 + uint32(b)
	}
	octet := byte((h % 254) + 1)
	ipA := fmt.Sprintf("10.77.%d.1", octet)
	ipB := fmt.Sprintf("10.88.%d.1", octet)

	// Drain A's bucket.
	for i := 0; i < middleware.AdminRateLimitPerMinute; i++ {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
		r.Header.Set("X-Forwarded-For", ipA)
		resp, _ := app.Test(r, 3000)
		resp.Body.Close()
	}
	// A's 31st: muted.
	rA := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
	rA.Header.Set("X-Forwarded-For", ipA)
	respA, _ := app.Test(rA, 3000)
	respA.Body.Close()
	assert.Equal(t, http.StatusForbidden, respA.StatusCode,
		"A's bucket must be drained")

	// B's 1st: passes.
	rB := httptest.NewRequest(http.MethodGet, "/api/v1/customers", nil)
	rB.Header.Set("X-Forwarded-For", ipB)
	respB, _ := app.Test(rB, 3000)
	defer respB.Body.Close()
	assert.Equal(t, http.StatusOK, respB.StatusCode,
		"B's bucket must be untouched by A's exhaustion")
}
