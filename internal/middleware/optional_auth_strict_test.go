package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// newOptionalAuthStrictApp mirrors newOptionalAuthApp but installs the
// strict variant added for T19 P1-7.
func newOptionalAuthStrictApp(secret string) *fiber.App {
	cfg := &config.Config{JWTSecret: secret}
	app := fiber.New()
	app.Use(middleware.OptionalAuthStrict(cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user_id": middleware.GetUserID(c),
			"team_id": middleware.GetTeamID(c),
		})
	})
	return app
}

// TestOptionalAuthStrict_NoHeader_PassesThrough — a missing Authorization
// header still passes through to anonymous. The strict variant ONLY differs
// from OptionalAuth on the bad-token case.
func TestOptionalAuthStrict_NoHeader_PassesThrough(t *testing.T) {
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestOptionalAuthStrict_ValidToken_SetsLocals — a good bearer still passes
// and populates locals.
func TestOptionalAuthStrict_ValidToken_SetsLocals(t *testing.T) {
	userID := uuid.NewString()
	teamID := uuid.NewString()
	tok := signSession(t, testhelpers.TestJWTSecret, userID, teamID, time.Hour)

	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, userID, body["user_id"])
	assert.Equal(t, teamID, body["team_id"])
}

// TestOptionalAuthStrict_GarbageBearer_Returns401 — T19 P1-7 regression.
// A malformed bearer must NOT silently downgrade to anonymous.
func TestOptionalAuthStrict_GarbageBearer_Returns401(t *testing.T) {
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"malformed bearer must 401 in the strict variant — T19 P1-7 fix")
}

// TestOptionalAuthStrict_ExpiredToken_Returns401 — expired tokens must
// surface 401, not silently anonymous-downgrade.
func TestOptionalAuthStrict_ExpiredToken_Returns401(t *testing.T) {
	tok := signSession(t, testhelpers.TestJWTSecret, uuid.NewString(), uuid.NewString(), -time.Hour)
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"expired bearer must 401 in the strict variant — T19 P1-7 fix")
}

// TestOptionalAuthStrict_WrongSecret_Returns401 — a token signed with a
// different secret must 401, not silently anonymous.
func TestOptionalAuthStrict_WrongSecret_Returns401(t *testing.T) {
	tok := signSession(t, "a-completely-different-secret-that-is-32-bytes!!", uuid.NewString(), uuid.NewString(), time.Hour)
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"wrong-secret JWT must 401 in the strict variant — T19 P1-7 fix")
}

// TestOptionalAuthStrict_NonBearerHeader_Returns401 — a non-Bearer
// Authorization header (e.g. Basic auth) must 401.
func TestOptionalAuthStrict_NonBearerHeader_Returns401(t *testing.T) {
	app := newOptionalAuthStrictApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"non-Bearer Authorization must 401 in the strict variant — T19 P1-7 fix")
}
