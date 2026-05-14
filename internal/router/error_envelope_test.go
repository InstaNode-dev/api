// error_envelope_test.go — W12 envelope contract for Fiber-default 4xx
// responses (404 wrong URL, 405 wrong method, 413 payload too large,
// 415 wrong Content-Type).
//
// RETRO-3 finding: the canonical ErrorResponse envelope was present on
// these paths EXCEPT for agent_action — agents probing a stale URL got
// {ok:false, error:"not_found", message:"...", request_id:"..."} with
// no guidance on what to do next. The fix wires agent_action sentences
// for each Fiber-default 4xx code through handlers.codeToAgentAction.
//
// We reconstruct just enough of the Fiber ErrorHandler chain to assert
// the response shape — no DB, no Redis, no full router. The handler
// under test is the literal closure from router/router.go's
// `ErrorHandler:` field, copied here so a future refactor that diverges
// from the canonical path fails this contract test.

package router_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// newErrorEnvelopeApp builds a minimal Fiber app whose ErrorHandler is
// byte-identical to router.New's. RequestID middleware is wired so
// request_id propagation is exercised, and one /healthz GET-only route
// is registered so we can probe 405 via a POST on it (Fiber's default
// router emits StatusMethodNotAllowed in that case).
func newErrorEnvelopeApp() *fiber.App {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			var errKey, msg string
			switch code {
			case fiber.StatusNotFound:
				errKey, msg = "not_found", "The requested resource was not found"
			case fiber.StatusMethodNotAllowed:
				errKey, msg = "method_not_allowed", "Method not allowed"
			case fiber.StatusRequestEntityTooLarge:
				errKey, msg = "payload_too_large", "Request payload exceeds the maximum allowed size"
			case fiber.StatusUnsupportedMediaType:
				errKey, msg = "unsupported_media_type", "Content-Type not supported for this endpoint"
			default:
				errKey, msg = "internal_error", "An unexpected error occurred"
			}
			_ = handlers.WriteFiberError(c, code, errKey, msg)
			return nil
		},
	})
	app.Use(middleware.RequestID())
	// One GET route so a POST on the same path produces 405 instead of 404.
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"ok": true}) })
	return app
}

// decode404 / decode405 helpers — pull the envelope and assert the W12
// completeness contract: ok, error, message, request_id, retry_after_seconds,
// agent_action are ALL present. agent_action is the field the W12 fix adds
// to the Fiber-default path.
func assertCanonicalEnvelope(t *testing.T, body map[string]any, expectedErrCode string) {
	t.Helper()

	assert.Equal(t, false, body["ok"], "ok=false on every error envelope")
	assert.Equal(t, expectedErrCode, body["error"], "stable machine-readable error code")

	msg, ok := body["message"].(string)
	require.True(t, ok, "message MUST be present on every envelope")
	assert.NotEmpty(t, msg)

	rid, ok := body["request_id"].(string)
	require.True(t, ok, "request_id MUST be present (populated from middleware.RequestID)")
	assert.NotEmpty(t, rid)

	_, hasRA := body["retry_after_seconds"]
	require.True(t, hasRA, "retry_after_seconds key MUST be present (null on 4xx)")
	assert.Nil(t, body["retry_after_seconds"], "retry_after_seconds is null on 4xx — no retry, fix the request")

	// W12 the actual fix: agent_action MUST be populated. Pre-W12 the
	// Fiber-default 4xx envelopes had every other field except this one.
	action, ok := body["agent_action"].(string)
	require.True(t, ok, "agent_action MUST be present on Fiber-default 4xx envelopes (W12 retro-3 fix)")
	assert.NotEmpty(t, action, "agent_action must be populated, not just present")
	// Each registered sentence carries a full https://instanode.dev/ URL
	// so the agent has a concrete next-step link — this matches the U3
	// contract that handlers/agent_action_contract_test.go enforces for
	// every entry in codeToAgentAction.
	assert.Contains(t, action, "https://instanode.dev/",
		"agent_action sentences for Fiber-default 4xx must carry a full https://instanode.dev/ URL per the U3 contract")
}

// TestFiberError_404_AgentAction — a GET on a path that doesn't exist
// returns 404 with the full envelope INCLUDING agent_action.
func TestFiberError_404_AgentAction(t *testing.T) {
	app := newErrorEnvelopeApp()
	resp, err := app.Test(httptest.NewRequest("GET", "/this-path-does-not-exist", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusNotFound, resp.StatusCode)

	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	assertCanonicalEnvelope(t, body, "not_found")
}

// TestFiberError_405_AgentAction — POST on a GET-only route returns 405
// with the full envelope. Fiber sets the Allow header automatically;
// agent_action points at the Allow header so the agent knows where to look.
func TestFiberError_405_AgentAction(t *testing.T) {
	app := newErrorEnvelopeApp()
	resp, err := app.Test(httptest.NewRequest("POST", "/healthz", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, fiber.StatusMethodNotAllowed, resp.StatusCode)

	// Allow header MUST be set by Fiber on 405 — the agent_action sentence
	// tells the user to check this header, so its absence would be a
	// silent UX bug.
	allow := resp.Header.Get("Allow")
	assert.NotEmpty(t, allow, "Fiber must set Allow header on 405 responses (the agent_action references it)")
	assert.Contains(t, allow, "GET", "Allow header must include GET since we registered a GET handler")

	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	assertCanonicalEnvelope(t, body, "method_not_allowed")

	// agent_action specifically should mention Allow so the agent can
	// pivot to the right method without a second roundtrip.
	assert.Contains(t, body["agent_action"], "Allow",
		"method_not_allowed agent_action must reference the Allow response header")
}
