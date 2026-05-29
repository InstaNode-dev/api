package middleware_test

// auth_beareronly_authp0_test.go — contract regression for the
// Bearer-only RequireAuth gate (PR #176 refactor, 2026-05-29).
//
// CLAUDE.md "Live API surface" documents Bearer-only auth for every
// route under RequireAuth — every CLI / MCP / SDK consumer is written
// against that contract. An earlier draft of AUTH-004 extended
// RequireAuth to fall back to the instanode_session cookie set by the
// magic-link / OAuth callbacks. That fallback was reverted before
// landing because:
//
//   - it would add a second auth mechanism every downstream surface
//     (CSRF review, cookie-domain config, route-level docs) would have
//     to reason about
//   - a future engineer might assume "cookie OR Bearer" is valid on
//     API routes and design new endpoints against the wrong contract
//
// The current shape: the callback drops a transient
// `instanode_session_exchange` cookie (Path=/auth/exchange, 30s TTL),
// the SPA POSTs /auth/exchange to swap it for the JWT in the body, and
// every API call from then on is Bearer-only. RequireAuth must NOT
// honour ANY cookie — this test locks that contract.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// TestRequireAuth_BearerOnly_NoCookieFallback — a request carrying ONLY
// the legacy `instanode_session` cookie (the pre-refactor name) AND a
// request carrying the new `instanode_session_exchange` cookie MUST both
// 401 when no Authorization: Bearer header is present. Future
// engineers reading the contract should see "RequireAuth = Bearer-only,
// no exceptions" and route auth design accordingly.
func TestRequireAuth_BearerOnly_NoCookieFallback(t *testing.T) {
	cfg := &config.Config{JWTSecret: "bearer-only-test-secret-32-bytes-min!"}
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/api/v1/protected",
		middleware.RequireAuth(cfg),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) },
	)

	cases := []struct {
		name   string
		cookie string
	}{
		{
			name:   "legacy instanode_session cookie ignored",
			cookie: "instanode_session=eyJhbGciOiJIUzI1NiJ9.fake.fake",
		},
		{
			name:   "transient exchange cookie ignored on API routes",
			cookie: "instanode_session_exchange=eyJhbGciOiJIUzI1NiJ9.fake.fake",
		},
		{
			name:   "arbitrary cookie name ignored",
			cookie: "session=eyJhbGciOiJIUzI1NiJ9.fake.fake",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/protected", nil)
			req.Header.Set("Cookie", tc.cookie)
			// Deliberately no Authorization header.
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"RequireAuth must 401 on cookie-only — Bearer-only contract")
			assert.Equal(t, `Bearer realm="instanode"`, resp.Header.Get("WWW-Authenticate"),
				"401 must carry RFC 6750 Bearer challenge — not Cookie")
		})
	}
}
