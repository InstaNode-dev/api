package middleware_test

// auth_envelope_test.go — W12 envelope-completeness contract for 401s.
//
// RETRO-3 finding: every middleware-emitted 401 (no header, malformed JWT,
// expired token, wrong secret, etc.) was missing the canonical envelope
// fields documented in handlers.ErrorResponse:
//
//   - message
//   - request_id
//   - retry_after_seconds  (always null on 4xx — "no retry, fix the request")
//
// agent_action + upgrade_url + ok + error were already present (see
// auth_agent_action_test.go for those assertions). This file adds the
// missing-fields contract so an agent inspecting any 401 from this API
// sees the same envelope shape that /openapi.json documents — no
// per-layer special cases.
//
// Lives next to auth_agent_action_test.go so a future regression in
// respondUnauthorized fails BOTH the agent_action and the envelope
// assertions, making the breakage obvious. Same minimal Fiber app
// scaffolding so we don't pull testhelpers (and its transitive handler
// imports) into the middleware package.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/middleware"
)

// newEnvelopeApp wires RequireAuth AFTER RequestID — so the envelope
// assertions can verify that the request_id field echoes the same UUID
// that RequestID() populated and the X-Request-ID response header carries.
func newEnvelopeApp() *fiber.App {
	cfg := &config.Config{JWTSecret: "envelope-test-secret-32-bytes-min-needed!"}
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Get("/api/v1/resources",
		middleware.RequireAuth(cfg),
		func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) },
	)
	return app
}

// TestRequireAuth_Envelope_NoHeader — bare unauthenticated call. The 401
// body MUST carry all six fields documented in the ErrorResponse schema:
// ok, error, message, request_id, retry_after_seconds, agent_action (and
// upgrade_url since it's an auth error). request_id must equal the
// X-Request-ID response header so support tickets correlate cleanly.
func TestRequireAuth_Envelope_NoHeader(t *testing.T) {
	app := newEnvelopeApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	// Required fields from handlers.ErrorResponse schema.
	assert.Equal(t, false, body["ok"], "ok=false on every error envelope")
	assert.Equal(t, "unauthorized", body["error"], "stable machine-readable error code")

	msg, ok := body["message"].(string)
	require.True(t, ok, "message MUST be present (W12 retro-3) — was missing pre-fix")
	assert.NotEmpty(t, msg, "message must be populated, not just present")

	// request_id must echo the X-Request-ID response header — same UUID
	// the RequestID() middleware populated into Fiber locals.
	headerReqID := resp.Header.Get("X-Request-ID")
	require.NotEmpty(t, headerReqID, "RequestID middleware must always set X-Request-ID")
	bodyReqID, ok := body["request_id"].(string)
	require.True(t, ok, "request_id MUST be present on every error envelope (W12 retro-3)")
	assert.Equal(t, headerReqID, bodyReqID,
		"body.request_id must equal the X-Request-ID header so agents can quote either when emailing support")

	// retry_after_seconds is unconditionally null on a 401 — the
	// remediation is re-auth, not a retry. Pin the JSON-null shape so a
	// future "missing key" regression fails this test (json.Unmarshal
	// produces nil for null, but the key must be present in the wire body).
	ra, hasRA := body["retry_after_seconds"]
	require.True(t, hasRA, "retry_after_seconds key MUST be present (null on 4xx) per W12 envelope contract")
	assert.Nil(t, ra, "retry_after_seconds MUST be null on 401 — no retry, fix the request")

	// agent_action + upgrade_url already covered by auth_agent_action_test.go;
	// assert presence here as a regression rail.
	assert.NotEmpty(t, body["agent_action"], "agent_action populated on 401")
	assert.Equal(t, "https://instanode.dev/login", body["upgrade_url"])
}

// TestRequireAuth_Envelope_InvalidJWT — same envelope on a malformed bearer.
// Confirms the contract is not specific to the "no header" branch but
// applies to every 401 path in respondUnauthorized.
func TestRequireAuth_Envelope_InvalidJWT(t *testing.T) {
	app := newEnvelopeApp()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	// Every documented field present.
	for _, k := range []string{"ok", "error", "message", "request_id", "retry_after_seconds", "agent_action", "upgrade_url"} {
		_, has := body[k]
		assert.True(t, has, "envelope key %q MUST be present on 401 (W12)", k)
	}
}

// TestRequireAuth_Envelope_RequestIDPropagatesIncoming — if the caller sends
// their own X-Request-ID, the 401 body's request_id field MUST echo it
// (not a fresh UUID). Operators correlating an agent's logs with the API's
// access logs rely on this.
func TestRequireAuth_Envelope_RequestIDPropagatesIncoming(t *testing.T) {
	app := newEnvelopeApp()
	const incoming = "11111111-1111-1111-1111-111111111111"

	req := httptest.NewRequest(http.MethodGet, "/api/v1/resources", nil)
	req.Header.Set("X-Request-ID", incoming)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, incoming, resp.Header.Get("X-Request-ID"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, incoming, body["request_id"],
		"body.request_id MUST echo the incoming X-Request-ID so the same correlator threads the whole request")
}
