package middleware_test

// auth_error_code_test.go — BUG-API-051 regression.
//
// RequireAuth's 401 envelope must carry an `error_code` sub-field that
// names which sub-case fired:
//
//	- missing_credentials  : no Authorization header / non-Bearer
//	- malformed_token      : header present but JWT/PAT won't parse
//	- expired_token        : JWT parsed cleanly but exp is in the past
//	- invalid_claims       : signature valid, uid/tid missing
//	- revoked_session      : jti in the session-revocation set
//
// Pre-fix every 401 from this middleware carried error=unauthorized with
// no sub-classification, so an agent had no way to branch "refresh the
// session" vs. "ask the user to log in again." We keep the top-level
// `error` keyword unchanged for back-compat.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

const authErrorCodeTestSecret = "p1-bundle-test-secret-32-bytes!!"

func newRequireAuthApp(t *testing.T) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: authErrorCodeTestSecret}
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/protected", middleware.RequireAuth(cfg), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app
}

// readErrorEnvelope unmarshals the body of a 401 and returns the JSON map.
func readErrorEnvelope(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var env map[string]any
	require.NoError(t, json.Unmarshal(body, &env), "401 body must be JSON: %s", string(body))
	return env
}

func TestRequireAuth_ErrorCode_MissingCredentials(t *testing.T) {
	app := newRequireAuthApp(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := readErrorEnvelope(t, resp)
	assert.Equal(t, "unauthorized", env["error"], "top-level error keyword unchanged")
	assert.Equal(t, "missing_credentials", env["error_code"],
		"BUG-API-051: no Authorization header → error_code=missing_credentials")
	assert.NotEmpty(t, env["request_id"], "request_id must be populated")
	assert.NotEmpty(t, env["agent_action"])
}

func TestRequireAuth_ErrorCode_MalformedToken(t *testing.T) {
	app := newRequireAuthApp(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer this.is.not-a-jwt")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	env := readErrorEnvelope(t, resp)
	assert.Equal(t, "malformed_token", env["error_code"],
		"BUG-API-051: unparseable JWT → error_code=malformed_token")
}

func TestRequireAuth_ErrorCode_ExpiredToken(t *testing.T) {
	app := newRequireAuthApp(t)

	claims := jwt.MapClaims{
		"uid":   "u-test",
		"tid":   "t-test",
		"email": "test@example.com",
		"jti":   "jti-expired",
		"iat":   time.Now().Add(-2 * time.Hour).Unix(),
		"exp":   time.Now().Add(-time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(authErrorCodeTestSecret))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+s)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	env := readErrorEnvelope(t, resp)
	assert.Equal(t, "expired_token", env["error_code"],
		"BUG-API-051: expired JWT (exp in the past) → error_code=expired_token")
}

func TestRequireAuth_ErrorCode_NonBearerScheme(t *testing.T) {
	app := newRequireAuthApp(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	env := readErrorEnvelope(t, resp)
	assert.Equal(t, "missing_credentials", env["error_code"],
		"non-Bearer scheme is treated as missing credentials (header isn't a Bearer at all)")
}
