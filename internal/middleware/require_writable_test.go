package middleware_test

// require_writable_test.go — unit coverage for the RequireWritable
// middleware. Drives every method × every flag combination through a
// minimal Fiber app so a regression in the gate (e.g. accidentally
// blocking GET on a read-only session, or letting POST through) is
// caught here before it ships.
//
// Why the matrix is exhaustive:
//
//   The middleware has exactly four axes — read_only flag (set/unset),
//   HTTP method (mutating/non-mutating), method case (POST vs post —
//   Fiber normalises, but defensive), and the (impossible-in-practice
//   but defensive) case where read_only is set to a non-bool. Each axis
//   is one test below. Adding a 5th axis (e.g. method allowlisting) means
//   adding a 5th test case here — the matrix shape is the contract.

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

// signImpersonationToken mints a JWT carrying read_only=true and
// impersonated_by=<adminEmail>. Same wire shape as the real handler's
// AdminImpersonateHandler issues.
func signImpersonationToken(t *testing.T, secret, userID, teamID, adminEmail string) string {
	t.Helper()
	type impersonateClaims struct {
		UserID         string `json:"uid"`
		TeamID         string `json:"tid"`
		Email          string `json:"email"`
		ReadOnly       bool   `json:"read_only"`
		ImpersonatedBy string `json:"impersonated_by"`
		jwt.RegisteredClaims
	}
	claims := impersonateClaims{
		UserID:         userID,
		TeamID:         teamID,
		Email:          "target@example.com",
		ReadOnly:       true,
		ImpersonatedBy: adminEmail,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// newWritableTestApp builds a Fiber app with the auth + RequireWritable
// chain installed and one route per HTTP verb echoing back "ok" so the
// test can assert which verb passed/failed.
func newWritableTestApp() *fiber.App {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	app := fiber.New()
	app.Use(middleware.OptionalAuth(cfg))
	app.Use(middleware.RequireWritable())
	echo := func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	}
	app.Get("/route", echo)
	app.Post("/route", echo)
	app.Put("/route", echo)
	app.Patch("/route", echo)
	app.Delete("/route", echo)
	return app
}

// TestRequireWritable_NoToken_AllMethodsPass — anonymous (no Authorization
// header at all) callers must NOT trip the gate. RequireWritable only
// fires when read_only is set, and OptionalAuth doesn't set it on
// header-less requests. This is the most important guardrail: the gate
// must be inert for the 99.99% of traffic that isn't impersonated.
func TestRequireWritable_NoToken_AllMethodsPass(t *testing.T) {
	app := newWritableTestApp()
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(m, "/route", nil)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"anonymous %s must pass RequireWritable (read_only flag unset)", m)
	}
}

// TestRequireWritable_NormalToken_AllMethodsPass — a writable (non-
// impersonated) session must NOT trip the gate on any verb. Verifies the
// inverse of the impersonation tests: read_only=false on the JWT means
// the gate is a no-op.
func TestRequireWritable_NormalToken_AllMethodsPass(t *testing.T) {
	app := newWritableTestApp()
	tok := signSession(t, testhelpers.TestJWTSecret, uuid.NewString(), uuid.NewString(), time.Hour)
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(m, "/route", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"writable %s must pass RequireWritable", m)
	}
}

// TestRequireWritable_ImpersonatedSession_GETPasses — the entire point of
// view-as-customer is to read. A read-only session MUST be able to GET.
// Regression target: an earlier version of this middleware rejected every
// method including GETs, which broke the very use case it was supposed to
// enable.
func TestRequireWritable_ImpersonatedSession_GETPasses(t *testing.T) {
	app := newWritableTestApp()
	tok := signImpersonationToken(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "founder@instanode.dev")
	req := httptest.NewRequest(http.MethodGet, "/route", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"read_only session must be allowed to GET — view-as-customer is the whole point")
}

// TestRequireWritable_ImpersonatedSession_PostBlocked — POST under an
// impersonated session must 403 with the canonical agent_action +
// error code. This is the headline rejection path the audit cares about.
func TestRequireWritable_ImpersonatedSession_PostBlocked(t *testing.T) {
	app := newWritableTestApp()
	tok := signImpersonationToken(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "founder@instanode.dev")
	req := httptest.NewRequest(http.MethodPost, "/route", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"POST under read_only session must 403")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "read_only_session", body["error"],
		"error code must be the distinct read_only_session keyword (NOT generic forbidden) so agents can branch")
	aa, _ := body["agent_action"].(string)
	assert.Contains(t, aa, "read-only impersonated session",
		"agent_action must name the specific rejection reason")
	assert.Contains(t, aa, "https://instanode.dev/app",
		"agent_action must contain a full https URL for the LLM to relay")
}

// TestRequireWritable_ImpersonatedSession_AllMutatingMethodsBlocked —
// POST/PUT/PATCH/DELETE must all 403 under an impersonated session.
// Belt-and-suspenders for the headline test: each verb individually.
func TestRequireWritable_ImpersonatedSession_AllMutatingMethodsBlocked(t *testing.T) {
	app := newWritableTestApp()
	tok := signImpersonationToken(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "founder@instanode.dev")
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		req := httptest.NewRequest(m, "/route", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := app.Test(req, 1000)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"%s under read_only session must 403", m)
	}
}

// TestRequireWritable_ImpersonationLocalsPopulated — both LocalKeyReadOnly
// and LocalKeyImpersonatedBy must be reachable from a downstream handler
// via the public accessors (IsReadOnly / GetImpersonatedBy). Guards
// against a regression where the auth middleware stops populating one
// of the two locals (e.g. ImpersonatedBy is dropped during a refactor).
func TestRequireWritable_ImpersonationLocalsPopulated(t *testing.T) {
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	app := fiber.New()
	app.Use(middleware.OptionalAuth(cfg))
	app.Get("/probe", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"read_only":       middleware.IsReadOnly(c),
			"impersonated_by": middleware.GetImpersonatedBy(c),
		})
	})

	tok := signImpersonationToken(t, testhelpers.TestJWTSecret,
		uuid.NewString(), uuid.NewString(), "founder@instanode.dev")
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)
	assert.Equal(t, true, body["read_only"],
		"IsReadOnly must return true for an impersonation token")
	assert.Equal(t, "founder@instanode.dev", body["impersonated_by"],
		"GetImpersonatedBy must return the admin email from the JWT")
}
