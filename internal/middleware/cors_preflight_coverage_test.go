package middleware_test

// cors_preflight_coverage_test.go — patch-coverage backfill for the two
// empty-token `continue` branches in cors_preflight_allowlist.go
// (lines 70 and 88) that the main BUG-API-066/067 test pair didn't hit.
//
// Both branches are reached when the comma-separated input contains an
// empty token between two non-empty values — a real browser would never
// emit that, but defensive parsing tolerates it. Without these tests the
// patch-coverage gate stays at 95% on this file.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// TestPreflightAllowlist_SkipsEmptyHeaderToken exercises the inner
// `if name == "" { continue }` at cors_preflight_allowlist.go:70. The
// preflight asks for `Authorization,, Content-Type` (note the double
// comma producing an empty middle token) which must NOT 403 — the empty
// token is skipped and both real headers pass.
func TestPreflightAllowlist_SkipsEmptyHeaderToken(t *testing.T) {
	app := fiber.New()
	app.Use(middleware.PreflightAllowlist(
		"GET,POST,OPTIONS",
		"Content-Type,Authorization",
	))
	app.Get("/x", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })

	req := httptest.NewRequest(http.MethodOptions, "/x", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Authorization,, Content-Type")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.NotEqual(t, http.StatusForbidden, resp.StatusCode,
		"empty middle token in AC-Request-Headers must be skipped, not rejected")
}

// TestPreflightAllowlist_SkipsEmptyAllowlistToken exercises the inner
// `if t == "" { continue }` of commaSet at cors_preflight_allowlist.go:88.
// Constructed by passing an allowMethods string with a double-comma so
// commaSet must skip the empty entry.
func TestPreflightAllowlist_SkipsEmptyAllowlistToken(t *testing.T) {
	app := fiber.New()
	// Note the double comma in the methods list — commaSet must skip it
	// so "GET" still registers as allowed.
	app.Use(middleware.PreflightAllowlist(
		"GET,,POST,OPTIONS",
		"Content-Type",
	))
	app.Get("/x", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })

	req := httptest.NewRequest(http.MethodOptions, "/x", nil)
	req.Header.Set("Origin", "https://instanode.dev")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.NotEqual(t, http.StatusForbidden, resp.StatusCode,
		"GET must remain allowed even when allowMethods has a stray empty token")
}
