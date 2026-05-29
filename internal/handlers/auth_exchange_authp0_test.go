package handlers_test

// auth_exchange_authp0_test.go — regression tests for the AUTH-004
// session-exchange handler (PR #176 refactor, 2026-05-29).
//
// The exchange handler is the browser-only bridge between the magic-link
// / OAuth callback and the SPA. Cookie semantics:
//
//   - Name:     instanode_session_exchange
//   - Path:     /auth/exchange
//   - Max-Age:  30 (callback-set)  /  0 (consumed by handler)
//   - HttpOnly + Secure (prod) + SameSite=Lax
//
// Bearer-only contract: RequireAuth still ignores cookies; the cookie's
// only consumer is POST /auth/exchange.

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

func buildExchangeApp(t *testing.T) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: "exchange-test-secret-not-used-for-verification"}
	authH := handlers.NewAuthHandler(nil, cfg) // exchange path does not touch DB
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/auth/exchange", authH.Exchange)
	return app
}

// TestAuthExchange_ConsumesCookie_ReturnsJWT_AndDeletesCookie — happy path:
// the SPA POSTs /auth/exchange with the cookie set by the callback, the
// handler returns the JWT in the body AND emits a Set-Cookie that clears
// the bridge cookie (Max-Age=0). Single-use semantics.
func TestAuthExchange_ConsumesCookie_ReturnsJWT_AndDeletesCookie(t *testing.T) {
	app := buildExchangeApp(t)
	const fakeJWT = "eyJhbGciOiJIUzI1NiJ9.fake-payload.fake-sig"

	req := httptest.NewRequest(http.MethodPost, "/auth/exchange", nil)
	req.Header.Set("Cookie", "instanode_session_exchange="+fakeJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"exchange with a valid cookie must 200")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), fakeJWT,
		"the JWT carried in the cookie must be returned in the response body")
	assert.Contains(t, string(body), `"ok":true`,
		"success body must carry ok:true")

	// Cookie cleared. Fiber emits an expires-in-past attribute (or
	// max-age=0) when the codec consumes our Expires/MaxAge clear
	// signal — both tell the browser to drop the cookie immediately.
	// Fiber lower-cases attribute names ("path=", "expires=") so we
	// compare against the lower-cased haystack.
	setCookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	lower := strings.ToLower(setCookies)
	require.NotEmpty(t, setCookies, "exchange must emit a Set-Cookie clearing the bridge cookie")
	assert.Contains(t, lower, "instanode_session_exchange=",
		"cleared cookie must be named instanode_session_exchange")
	clearSignal := strings.Contains(lower, "max-age=0") || strings.Contains(lower, "expires=")
	assert.True(t, clearSignal,
		"cleared cookie must carry Max-Age=0 or an expires-in-past header; got: %s", setCookies)
	assert.Contains(t, lower, "path=/auth/exchange",
		"cleared cookie must keep the same Path so the browser actually drops it")
}

// TestAuthExchange_NoCookie_Returns400 — calling /auth/exchange with no
// bridge cookie is a SPA programming error or an expired transient
// window. Return 400 with a clear error keyword so the SPA can surface
// "please sign in again".
func TestAuthExchange_NoCookie_Returns400(t *testing.T) {
	app := buildExchangeApp(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/exchange", nil)
	// No Cookie header at all.
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"missing cookie must 400 (not 401 — there's no auth attempt to reject)")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "cookie_missing_or_expired",
		"error envelope must carry the cookie_missing_or_expired keyword")
}

// TestAuthExchange_ExpiredCookie_Returns400 — when the browser has dropped
// the 30s cookie (transient window closed), the request reaches the
// handler with no cookie at all (browser strips it). The handler treats
// this the same as no-cookie: 400 cookie_missing_or_expired.
//
// We model "expired" as "Cookie header explicitly carries an empty value"
// to exercise the second arm of the guard — a real browser drops the
// cookie entirely, which the no-cookie test above covers.
func TestAuthExchange_ExpiredCookie_Returns400(t *testing.T) {
	app := buildExchangeApp(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/exchange", nil)
	req.Header.Set("Cookie", "instanode_session_exchange=")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"empty/expired cookie value must 400")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "cookie_missing_or_expired")
}
