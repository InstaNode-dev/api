package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// newOptionalAuthApp returns a minimal Fiber app with OptionalAuth installed.
// The single route echoes the auth locals back as JSON for inspection.
func newOptionalAuthApp(secret string) *fiber.App {
	cfg := &config.Config{JWTSecret: secret}
	app := fiber.New()
	app.Use(middleware.OptionalAuth(cfg))
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"user_id": middleware.GetUserID(c),
			"team_id": middleware.GetTeamID(c),
		})
	})
	return app
}

// signSession builds a session JWT (same structure as issued by the auth handler).
func signSession(t *testing.T, secret, userID, teamID string, expiry time.Duration) string {
	t.Helper()
	type sessionClaims struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		Email  string `json:"email"`
		jwt.RegisteredClaims
	}
	claims := sessionClaims{
		UserID: userID,
		TeamID: teamID,
		Email:  "test@instant.dev",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// TestOptionalAuth_NoHeader_PassesThrough verifies that requests without an
// Authorization header reach the handler with empty auth locals.
func TestOptionalAuth_NoHeader_PassesThrough(t *testing.T) {
	app := newOptionalAuthApp(testhelpers.TestJWTSecret)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, "", body["user_id"], "user_id must be empty for unauthenticated request")
	assert.Equal(t, "", body["team_id"], "team_id must be empty for unauthenticated request")
}

// TestOptionalAuth_ValidToken_SetsLocals verifies that a valid bearer token
// populates user_id and team_id in Fiber locals.
func TestOptionalAuth_ValidToken_SetsLocals(t *testing.T) {
	userID := uuid.NewString()
	teamID := uuid.NewString()
	tok := signSession(t, testhelpers.TestJWTSecret, userID, teamID, time.Hour)

	app := newOptionalAuthApp(testhelpers.TestJWTSecret)
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

// TestOptionalAuth_InvalidToken_PassesThrough verifies that a malformed bearer
// token does NOT return 401 — the request continues as anonymous.
func TestOptionalAuth_InvalidToken_PassesThrough(t *testing.T) {
	app := newOptionalAuthApp(testhelpers.TestJWTSecret)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer this-is-not-a-jwt")

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"invalid bearer token must not return 401 — OptionalAuth should fail open")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, "", body["user_id"])
	assert.Equal(t, "", body["team_id"])
}

// TestOptionalAuth_ExpiredToken_PassesThrough verifies that an expired token
// does NOT block the request — continues as anonymous.
func TestOptionalAuth_ExpiredToken_PassesThrough(t *testing.T) {
	tok := signSession(t, testhelpers.TestJWTSecret, uuid.NewString(), uuid.NewString(), -time.Hour)

	app := newOptionalAuthApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"expired bearer token must not return 401 — OptionalAuth should fail open")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, "", body["user_id"])
	assert.Equal(t, "", body["team_id"])
}

// TestOptionalAuth_WrongSecret_PassesThrough verifies that a token signed with
// a different secret does NOT block the request.
func TestOptionalAuth_WrongSecret_PassesThrough(t *testing.T) {
	tok := signSession(t, "a-completely-different-secret-that-is-32-bytes!!", uuid.NewString(), uuid.NewString(), time.Hour)

	app := newOptionalAuthApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, "", body["user_id"])
	assert.Equal(t, "", body["team_id"])
}

// TestOptionalAuth_MissingClaims_PassesThrough verifies that a valid JWT with
// empty uid/tid does not populate auth locals (treated as anonymous).
func TestOptionalAuth_MissingClaims_PassesThrough(t *testing.T) {
	// Sign a token with empty uid/tid — technically valid signature but missing claims.
	tok := signSession(t, testhelpers.TestJWTSecret, "", "", time.Hour)

	app := newOptionalAuthApp(testhelpers.TestJWTSecret)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, "", body["user_id"])
	assert.Equal(t, "", body["team_id"])
}

// TestOptionalAuth_BearerPrefixOnly_PassesThrough verifies that "Bearer " with
// no token string is treated as anonymous (not a crash).
func TestOptionalAuth_BearerPrefixOnly_PassesThrough(t *testing.T) {
	app := newOptionalAuthApp(testhelpers.TestJWTSecret)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer ") // space but no token

	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
