package middleware_test

// cors_preflight_allowlist_test.go — BUG-API-066 / BUG-API-067 regression.
//
// Fiber's CORS middleware sets Access-Control-Allow-* response headers
// but does NOT validate the inbound Access-Control-Request-Method /
// Access-Control-Request-Headers against the allowlist. A preflight
// asking for TRACE or `Cookie` therefore got a 204 with the allowlisted
// methods in the response — not a 403. PreflightAllowlist is a pre-CORS
// gate that rejects such preflights with 403.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

func newPreflightApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New()
	app.Use(middleware.PreflightAllowlist(
		"GET,POST,PUT,PATCH,DELETE,OPTIONS",
		"Content-Type,Authorization,X-Request-ID",
	))
	app.Get("/whoami", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })
	return app
}

// BUG-API-066: a preflight asking for TRACE is rejected with 403.
func TestPreflightAllowlist_RejectsTRACEMethod(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "TRACE")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"BUG-API-066: TRACE preflight must be 403 (not 204)")
}

// BUG-API-066: a preflight asking for CONNECT is also rejected (defence
// against the "any non-allowlisted method" class).
func TestPreflightAllowlist_RejectsCONNECTMethod(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "CONNECT")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"BUG-API-066: CONNECT preflight must be 403")
}

// BUG-API-067: a preflight asking for `Cookie` in the request headers is
// rejected with 403.
func TestPreflightAllowlist_RejectsCookieHeader(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Cookie")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"BUG-API-067: preflight with Cookie header must be 403")
}

// BUG-API-067: even a mix of allowed + disallowed headers fails.
func TestPreflightAllowlist_RejectsMixedHeaders(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Set-Cookie")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"BUG-API-067: any non-allowlisted header in the comma list is 403")
}

// Sanity: a fully legitimate preflight passes through unchanged.
func TestPreflightAllowlist_AllowsLegitimatePreflight(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// No real CORS middleware downstream — OPTIONS falls through with
	// no route → 404 or 405. The middleware must NOT 403.
	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
		"legitimate preflight must not be 403")
}

// Sanity: non-OPTIONS requests pass through without inspection.
func TestPreflightAllowlist_IgnoresGET(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "TRACE") // not a real preflight

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"non-preflight requests must not be inspected")
}

// Sanity: an OPTIONS with no Access-Control-Request-Method is not a CORS
// preflight; it must fall through.
func TestPreflightAllowlist_IgnoresBareOPTIONS(t *testing.T) {
	app := newPreflightApp(t)

	req := httptest.NewRequest(http.MethodOptions, "/whoami", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
		"bare OPTIONS (no Origin/AC-Request-Method) must not be 403")
}
