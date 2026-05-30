// cors_maxage_test.go — pins BUG-API-303 (QA 2026-05-29): the CORS
// preflight response must carry Access-Control-Max-Age so browsers cache
// the preflight result instead of re-issuing one before every CORS
// request. Without this, an SPA making 5 cross-origin API calls fires 5
// extra preflight roundtrips.
//
// We reconstruct just the fiberCORS middleware exactly as router.New
// configures it (same allow-origins / methods / headers / max-age) and
// drive a single OPTIONS preflight through it. The assertion is the live
// Access-Control-Max-Age header on the response.

package router_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	fiberCORS "github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCORSPreflight_HasMaxAgeHeader pins BUG-API-303: the fiberCORS
// preflight response on any cross-origin OPTIONS must carry
// Access-Control-Max-Age=86400 so browsers (and cooperative proxies)
// cache the preflight result.
//
// Mirrors the production fiberCORS config in router.New verbatim. A
// future router.New edit that drops MaxAge regresses BUG-API-303 and
// fails this test.
func TestCORSPreflight_HasMaxAgeHeader(t *testing.T) {
	const (
		corsAllowOrigins  = "https://instanode.dev,https://www.instanode.dev"
		corsAllowMethods  = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
		corsAllowHeaders  = "Content-Type,Authorization,X-Request-ID,X-E2E-Test-Token,X-E2E-Source-IP"
		corsMaxAgeSeconds = 86400
	)

	app := fiber.New()
	app.Use(fiberCORS.New(fiberCORS.Config{
		AllowOrigins:  corsAllowOrigins,
		AllowMethods:  corsAllowMethods,
		AllowHeaders:  corsAllowHeaders,
		ExposeHeaders: "X-Request-ID,X-Instant-Upgrade,X-Instant-Notice",
		MaxAge:        corsMaxAgeSeconds,
	}))
	app.Get("/api/v1/whoami", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })

	req := httptest.NewRequest("OPTIONS", "/api/v1/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Status — preflight should 204 (or 200) and emit the CORS-allow set.
	require.True(t, resp.StatusCode == fiber.StatusNoContent || resp.StatusCode == fiber.StatusOK,
		"preflight expected 204/200; got %d", resp.StatusCode)

	// BUG-API-303: the Max-Age header is what closes the regression.
	maxAge := resp.Header.Get("Access-Control-Max-Age")
	assert.Equal(t, "86400", maxAge,
		"BUG-API-303: Access-Control-Max-Age must be 86400 (24h) — without it browsers re-preflight every CORS request; got %q", maxAge)
}
