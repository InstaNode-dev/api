package middleware_test

// auth_agent_action_test.go — agent_action contract tests for RequireAuth.
//
// RETRO-2026-05-12 fix: an unauthenticated call to /api/v1/resources (and
// every other RequireAuth-gated endpoint) was returning the bare three-key
// shape `{ok:false, error:"unauthorized"}` — no agent_action, no upgrade_url.
// Downstream handlers that go through respondError already emit the
// agent_action sentence for the "unauthorized" code (via codeToAgentAction),
// but middleware bypasses that helper to avoid a circular import. The fix
// inlines the same prose + login URL directly in respondUnauthorized so an
// agent inspecting any 401 from this API gets the same remediation guidance
// regardless of which layer rejected the request.
//
// These tests live in their own file so they don't pull internal/testhelpers
// (which transitively imports internal/handlers and would risk import
// cycles with unrelated changes in that package).

import (
	"encoding/json"
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

// agentActionTestJWTSecret is intentionally distinct from audTestJWTSecret
// (auth_audience_test.go) so a token signed in this file can be used as the
// "wrong secret" probe — RequireAuth rejecting a wrong-secret token must
// produce the same agent_action shape as a token-shaped-but-not-bearer
// rejection.
const agentActionTestJWTSecret = "agent-action-secret-32-bytes-min-test!!!"

// newAgentActionApp builds a minimal Fiber app with RequireAuth gating one
// route. The route never runs on failure — every assertion below targets
// the 401 body shape RequireAuth itself emits.
func newAgentActionApp() *fiber.App {
	cfg := &config.Config{JWTSecret: agentActionTestJWTSecret}
	app := fiber.New()
	app.Get("/api/v1/resources",
		middleware.RequireAuth(cfg),
		func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{"ok": true})
		},
	)
	return app
}

// signValidSession produces a JWT that would normally pass RequireAuth.
// Used to build "negative" tokens (wrong secret, expired) where the token
// must be syntactically valid but logically rejected.
func signValidSession(t *testing.T, secret string, expiry time.Duration) string {
	t.Helper()
	type sessionClaims struct {
		UserID string `json:"uid"`
		TeamID string `json:"tid"`
		Email  string `json:"email"`
		jwt.RegisteredClaims
	}
	c := sessionClaims{
		UserID: uuid.NewString(),
		TeamID: uuid.NewString(),
		Email:  "test@instant.dev",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiry)),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(secret))
	require.NoError(t, err)
	return signed
}

// assertAgentActionUnauthorized asserts the canonical 401 body shape served
// by respondUnauthorized: error="unauthorized", agent_action mentions login,
// upgrade_url points at the login page. Centralised so the table-test cases
// below don't repeat the assertions and the contract stays in one place.
func assertAgentActionUnauthorized(t *testing.T, resp *http.Response) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "unauthorized", body["error"],
		"middleware-emitted 401 must use the same 'unauthorized' code that handlers.codeToAgentAction matches on")

	action, ok := body["agent_action"].(string)
	require.True(t, ok, "agent_action must be a string field on every 401 from RequireAuth — this is the whole point of the fix")
	assert.NotEmpty(t, action, "agent_action must be populated, not just present")
	assert.Contains(t, action, "INSTANODE_TOKEN",
		"agent_action must name the env var the user sets — otherwise the agent has nothing concrete to mention")
	assert.Contains(t, action, "https://instanode.dev/login",
		"agent_action must include the login URL inline so the agent's prose carries the link without a second lookup")

	url, ok := body["upgrade_url"].(string)
	require.True(t, ok, "upgrade_url must be present so MPP-style agents can follow it programmatically")
	assert.Equal(t, "https://instanode.dev/login", url,
		"upgrade_url for 'unauthorized' must point at the login page, not pricing")
}

// TestRequireAuth_NoHeader_EmitsAgentAction — the bare-call case. Before the
// fix this returned {ok:false, error:"unauthorized"} only. After the fix it
// carries the full agent_action body shape.
func TestRequireAuth_NoHeader_EmitsAgentAction(t *testing.T) {
	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}

// TestRequireAuth_MalformedBearer_EmitsAgentAction — non-"Bearer " prefix.
// Same shape as no-header.
func TestRequireAuth_MalformedBearer_EmitsAgentAction(t *testing.T) {
	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // wrong scheme
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}

// TestRequireAuth_InvalidJWT_EmitsAgentAction — garbage after "Bearer ".
// JWT parse fails; agent_action shape preserved.
func TestRequireAuth_InvalidJWT_EmitsAgentAction(t *testing.T) {
	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt-token")
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}

// TestRequireAuth_WrongSecret_EmitsAgentAction — a syntactically valid JWT
// signed with a different secret. ParseWithClaims fails verification.
func TestRequireAuth_WrongSecret_EmitsAgentAction(t *testing.T) {
	tok := signValidSession(t, "completely-different-secret-32-bytes-here!!!", time.Hour)

	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}

// TestRequireAuth_ExpiredJWT_EmitsAgentAction — a JWT signed with the right
// secret but already past its exp. The "expired" case is the most common
// in production (users come back to the dashboard after a few days); the
// agent_action prose is the same as every other 401.
func TestRequireAuth_ExpiredJWT_EmitsAgentAction(t *testing.T) {
	tok := signValidSession(t, agentActionTestJWTSecret, -time.Hour)

	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}

// TestRequireAuth_BearerOnly_EmitsAgentAction — "Bearer " literal with no
// token after it. The 8-byte length guard short-circuits before any JWT
// parsing.
func TestRequireAuth_BearerOnly_EmitsAgentAction(t *testing.T) {
	app := newAgentActionApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer ") // space but no token
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assertAgentActionUnauthorized(t, resp)
}
