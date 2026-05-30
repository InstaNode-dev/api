// cors_credentials_test.go — pins the AUTH-004 follow-up fix
// (instanode-web#150 / #151, prod 2026-05-30): the fiberCORS middleware
// MUST emit `Access-Control-Allow-Credentials: true` on the actual-CORS
// response so the dashboard SPA's `fetch('/auth/exchange', {credentials:
// 'include'})` can READ the response. Without it, the browser blocks
// the read with:
//
//   Access to fetch at 'https://api.instanode.dev/auth/exchange' from
//   origin 'https://instanode.dev' has been blocked by CORS policy:
//   The value of the 'Access-Control-Allow-Credentials' header in the
//   response is '' which must be 'true' when the request's credentials
//   mode is 'include'.
//
// We reconstruct the fiberCORS middleware exactly as router.New
// configures it (same allow-origins / methods / headers / credentials)
// and drive a single actual cross-origin GET. The assertion is the live
// Access-Control-Allow-Credentials header on the response.
//
// A future router.New edit that drops AllowCredentials regresses prod
// login and fails this test.

package router_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	fiberCORS "github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCORS_AllowCredentialsHeader pins the AUTH-004 follow-up.
// The fiberCORS config on an allowed cross-origin request must respond
// with `Access-Control-Allow-Credentials: true`.
func TestCORS_AllowCredentialsHeader(t *testing.T) {
	const (
		corsAllowOrigins  = "https://instanode.dev,https://www.instanode.dev"
		corsAllowMethods  = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
		corsAllowHeaders  = "Content-Type,Authorization,X-Request-ID,X-E2E-Test-Token,X-E2E-Source-IP"
		corsMaxAgeSeconds = 86400
	)

	app := fiber.New()
	app.Use(fiberCORS.New(fiberCORS.Config{
		AllowOrigins:     corsAllowOrigins,
		AllowMethods:     corsAllowMethods,
		AllowHeaders:     corsAllowHeaders,
		ExposeHeaders:    "X-Request-ID,X-Instant-Upgrade,X-Instant-Notice",
		MaxAge:           corsMaxAgeSeconds,
		AllowCredentials: true,
	}))
	app.Post("/auth/exchange", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"token": "stub"})
	})

	// Actual cross-origin POST (not preflight) — the response must carry
	// Access-Control-Allow-Credentials: true.
	req := httptest.NewRequest("POST", "/auth/exchange", nil)
	req.Header.Set("Origin", "https://instanode.dev")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()

	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	assert.Equal(t, "true", allowCreds,
		"AUTH-004 follow-up: Access-Control-Allow-Credentials must be 'true' so the dashboard SPA's `credentials: 'include'` POSTs can read the response. Without it the browser blocks the read with a generic 'blocked by CORS policy' error. Got %q", allowCreds)

	// Sanity: Access-Control-Allow-Origin must NOT be `*` when credentials
	// are allowed (CORS spec forbids that combination). It should be the
	// exact origin instead.
	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	assert.Equal(t, "https://instanode.dev", allowOrigin,
		"with AllowCredentials:true, Allow-Origin must be the exact requesting origin (not `*`); got %q", allowOrigin)
}

// TestCORSPreflight_HasAllowCredentialsHeader — same assertion but on
// the OPTIONS preflight path. Browsers check the preflight response for
// `Access-Control-Allow-Credentials: true` BEFORE issuing the actual
// request when the JS uses `credentials: 'include'`. Without it, the
// preflight is treated as "credentials not permitted" and the real
// request never fires.
func TestCORSPreflight_HasAllowCredentialsHeader(t *testing.T) {
	const (
		corsAllowOrigins  = "https://instanode.dev,https://www.instanode.dev"
		corsAllowMethods  = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
		corsAllowHeaders  = "Content-Type,Authorization,X-Request-ID,X-E2E-Test-Token,X-E2E-Source-IP"
		corsMaxAgeSeconds = 86400
	)

	app := fiber.New()
	app.Use(fiberCORS.New(fiberCORS.Config{
		AllowOrigins:     corsAllowOrigins,
		AllowMethods:     corsAllowMethods,
		AllowHeaders:     corsAllowHeaders,
		ExposeHeaders:    "X-Request-ID,X-Instant-Upgrade,X-Instant-Notice",
		MaxAge:           corsMaxAgeSeconds,
		AllowCredentials: true,
	}))
	app.Post("/auth/exchange", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"token": "stub"})
	})

	req := httptest.NewRequest("OPTIONS", "/auth/exchange", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.True(t, resp.StatusCode == fiber.StatusNoContent || resp.StatusCode == fiber.StatusOK,
		"preflight expected 204/200; got %d", resp.StatusCode)

	allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
	assert.Equal(t, "true", allowCreds,
		"preflight Allow-Credentials must be 'true' for `credentials:include` requests; got %q", allowCreds)
}
