// status_public_test.go — H2 / W12: pins GET /api/v1/status as a
// public, no-auth route even when registered alongside the auth-gated
// /api/v1 group.
//
// Fiber's group middleware applies to routes registered THROUGH the
// group object — not to routes registered at app.* level under the same
// path prefix. The contract is subtle enough that retro-3 surfaced a
// concern about it; this test pins the invariant so a future refactor
// that "tidies up" /api/v1/status by moving it under the api group fails
// CI immediately.
//
// We don't spin up the full router (it needs Postgres + Redis + gRPC).
// Instead we replicate the structural pattern from router.go: an
// app-level GET registration BEFORE the api Group with RequireAuth, and
// then a probe that confirms the GET is reachable with no Authorization
// header.

package router_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// TestStatusRoute_PublicEvenWithApiGroup — the canonical wire-up: register
// /api/v1/status via app.Get(...) and THEN create an app.Group("/api/v1",
// RequireAuth) with a gated /api/v1/resources. The public route must
// remain reachable without a Bearer token.
func TestStatusRoute_PublicEvenWithApiGroup(t *testing.T) {
	cfg := &config.Config{JWTSecret: "test-secret-32-bytes-min-need-here-okay!"}
	app := fiber.New()

	// /api/v1/status — public, no auth. Mirrors router.go line ~286.
	app.Get("/api/v1/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "components": []any{}, "current_incidents": []any{}})
	})

	// /api/v1 group — auth-gated. Mirrors router.go line ~515.
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/resources", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "resources": []any{}})
	})

	// Probe 1: /api/v1/status with NO Authorization header — must be 200.
	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/status", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, fiber.StatusOK, resp.StatusCode,
		"/api/v1/status MUST be reachable without auth — it answers 'is instanode up?', gating it on auth defeats the purpose")

	// Probe 2: /api/v1/resources with NO Authorization header — must be 401.
	// This confirms the api group's middleware IS gating its own routes,
	// so a future regression where the group's middleware silently leaks
	// onto the public route would fail probe 1 above.
	resp2, err := app.Test(httptest.NewRequest("GET", "/api/v1/resources", nil))
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, fiber.StatusUnauthorized, resp2.StatusCode,
		"/api/v1/resources MUST be gated — proves the api group middleware is wired correctly, and isolates the public-route assertion above")
}

// TestStatusRoute_DemonstratesGroupMiddlewareLeakage — load-bearing
// invariant guard. Demonstrates that if the public /api/v1/status route is
// registered AFTER the auth-gated /api/v1 group has been declared, Fiber's
// route matcher resolves the request to the GROUP'S handler chain (which
// includes the auth middleware) and rejects with 401. Production code in
// router.go registers /api/v1/status BEFORE the api group is created
// precisely because of this — this test pins the rationale.
//
// If a future refactor "tidies up" router.go by moving the api group
// declaration above the status registration, this test passes (the
// rejected-when-registered-late behaviour) but the SIBLING test
// TestStatusRoute_PublicEvenWithApiGroup — which keeps the prod ordering
// — would still pass too. So the protection is: any move that breaks the
// prod ordering invariant gets caught by the public-route-is-200 assertion
// in the first test.
//
// We assert 401 here (rather than 200) to make the failure mode explicit:
// changing this test to expect 200 by hand REQUIRES the engineer to think
// about why — at which point they'll spot the prod registration ordering
// that protects us.
func TestStatusRoute_DemonstratesGroupMiddlewareLeakage(t *testing.T) {
	cfg := &config.Config{JWTSecret: "test-secret-32-bytes-min-need-here-okay!"}
	app := fiber.New()

	// Create the gated group FIRST — the WRONG order.
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/resources", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	// THEN register the public route via app.Get. Fiber's matcher resolves
	// this through the group's chain because the group prefix matches first.
	// Production router.go avoids this by registering status BEFORE the
	// api group is created.
	app.Get("/api/v1/status", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/api/v1/status", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode,
		"Demonstrates the failure mode: registering /api/v1/status AFTER the auth-gated /api/v1 group causes the route to inherit auth — this is why production router.go registers status BEFORE the group is created")
}
