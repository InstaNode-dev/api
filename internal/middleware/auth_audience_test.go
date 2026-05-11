package middleware_test

// auth_audience_test.go — RFC 8707 Resource Indicators tests.
//
// These tests live in a separate file (rather than being added to
// auth_test.go) so they can avoid importing internal/testhelpers, which
// transitively pulls internal/handlers. Handlers currently has unrelated
// in-flight changes from other agents; keeping these tests isolated lets
// them compile without the rest of the handlers package being clean.

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
)

// audTestJWTSecret matches the inline secret used in dpop_test.go.
const audTestJWTSecret = "test-secret-that-is-at-least-32-bytes-long!!"

// signSessionWithAudience builds a session JWT with an explicit `aud` claim.
// audience may be a single string or a comma-separated list (the JWT
// RegisteredClaims.Audience field is jwt.ClaimStrings which accepts both).
func signSessionWithAudience(t *testing.T, audience []string) string {
	t.Helper()
	type cnfClaim struct {
		JKT string `json:"jkt,omitempty"`
	}
	type sessionClaims struct {
		UserID string    `json:"uid"`
		TeamID string    `json:"tid"`
		Email  string    `json:"email"`
		Cnf    *cnfClaim `json:"cnf,omitempty"`
		jwt.RegisteredClaims
	}
	c := sessionClaims{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		Email:  "user@instanode.dev",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        uuid.NewString(),
			Audience:  jwt.ClaimStrings(audience),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(audTestJWTSecret))
	require.NoError(t, err)
	return signed
}

func newAudApp() *fiber.App {
	cfg := &config.Config{JWTSecret: audTestJWTSecret}
	app := fiber.New()
	app.Get("/api/v1/resources",
		middleware.RequireAuth(cfg),
		func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		},
	)
	return app
}

// TestAudience_Match: a token whose aud equals the canonical resource URL
// passes through.
func TestAudience_Match(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	tok := signSessionWithAudience(t, []string{"https://api.instanode.dev"})

	app := newAudApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestAudience_Mismatch: a token whose aud does not contain the canonical
// resource URL is rejected with 401 invalid_token.
func TestAudience_Mismatch(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	tok := signSessionWithAudience(t, []string{"https://storage.instanode.dev"})

	app := newAudApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
	assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "audience mismatch")
}

// TestAudience_NoClaim_BackCompat: a token with no aud claim at all still
// works (back-compat for existing dashboard sessions).
func TestAudience_NoClaim_BackCompat(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	tok := signSessionWithAudience(t, nil)

	app := newAudApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a token with no aud claim should still pass (back-compat)")
}

// TestAudience_MultipleAud_AnyMatch: the token may declare multiple
// audiences; at least one must match the canonical resource URL.
func TestAudience_MultipleAud_AnyMatch(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	tok := signSessionWithAudience(t, []string{
		"https://other.example.com",
		"https://api.instanode.dev",
	})

	app := newAudApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
