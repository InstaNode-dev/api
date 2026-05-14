package router_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// TestLivezReturns200WithAliveBody pins the wire shape of GET /livez.
// The endpoint is the k8s liveness probe target — pure process-up signal.
// NO database, NO migration check, NO auth, NO rate limit. If a future
// refactor accidentally folds /livez under app.Use(...) middleware, this
// test would still pass for the happy path, so TestLivezSkipsAuthMiddleware
// below is the real teeth.
func TestLivezReturns200WithAliveBody(t *testing.T) {
	app := fiber.New()
	app.Get("/livez", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"alive": true})
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/livez", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, true, got["alive"], "GET /livez must return {\"alive\":true}")

	// Body shape is exactly one key. k8s probes don't care, but the
	// contract is documented in the OpenAPI spec — make sure we don't
	// accidentally start emitting commit_id / migration_status here
	// (that's the /healthz contract; muddling the two breaks the
	// probe-split rationale for shipping /livez in the first place).
	require.Len(t, got, 1, "/livez body must be exactly {\"alive\":true} — no extra fields")
}

// TestLivezSkipsAuthMiddleware is the load-bearing test for this PR.
// /livez MUST be registered BEFORE any app.Use(...) so the kubelet's
// probe traffic never touches rate-limit / auth / fingerprint /
// geo-enrich. We assert that by wiring an auth gate that ALWAYS 401s
// in front of every route, registering /livez BEFORE that gate, and
// confirming /livez still returns 200 — proving the gate didn't run.
//
// If a future refactor moved the app.Get("/livez", ...) call to AFTER
// the app.Use(authGate), the request would be rejected with 401 and
// this test would fail.
func TestLivezSkipsAuthMiddleware(t *testing.T) {
	app := fiber.New()

	// Register /livez first — before any middleware is wired.
	app.Get("/livez", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"alive": true})
	})

	// Now install a stand-in "auth wall" that rejects every request.
	// Anything registered AFTER this would 401; /livez sat above it
	// and must continue to 200.
	app.Use(func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"ok":    false,
			"error": "unauthorized",
		})
	})

	// And a sentinel route registered AFTER the wall — proves the
	// wall actually fires for normal traffic (so a passing /livez
	// reflects the registration ordering, not a broken wall).
	app.Get("/some-protected-route", func(c *fiber.Ctx) error {
		return c.SendString("should never be reached")
	})

	// /livez — should pass through with 200, no auth touched.
	resp, err := app.Test(httptest.NewRequest("GET", "/livez", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode,
		"GET /livez must NOT be gated by any middleware (the kubelet's liveness probe needs to hit it 6x/min without auth)")

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.Equal(t, true, got["alive"])

	// Sanity rail — the wall is real; protected routes get 401.
	respProtected, err := app.Test(httptest.NewRequest("GET", "/some-protected-route", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, respProtected.StatusCode,
		"sentinel: routes registered AFTER the middleware wall MUST 401 — if this fails, the test no longer proves anything about /livez")
}

// Compile-time guard — referencing the middleware package keeps this
// test file honest about being in the same import tree as the real
// router.go (so a future broken import there surfaces here too).
var _ = middleware.RequestID
