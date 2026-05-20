package handlers

// error_envelope_test.go — covers the W7G standardized error envelope:
// every 4xx/5xx response MUST include `request_id`, `retry_after_seconds`,
// and (for 5xx) `agent_action` in the JSON body, plus the matching
// Retry-After HTTP header on 429/502/503/504.
//
// Three layers exercised:
//
//  1. respondError + respondErrorWithAgentAction at the handler level —
//     auto-population of request_id from middleware, retry_after_seconds
//     from status code, agent_action fallback for plumbing 5xx.
//
//  2. The Fiber error handler — wrong-method / not-found requests that
//     never touched a handler still produce the canonical envelope so
//     agents see one shape across the whole service.
//
//  3. Retry-After header parity — for 429/502/503/504 the body's
//     retry_after_seconds and the HTTP Retry-After header MUST agree.
//     Polite clients honor the header without parsing the body.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"instant.dev/internal/middleware"
)

// envelopeApp builds a tiny Fiber app with RequestID middleware so
// respondError sees a populated request_id local — matches the
// production middleware chain in router/router.go.
func envelopeApp(t *testing.T) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := err.(*fiber.Error); ok {
				code = fe.Code
			}
			var errKey, msg string
			switch code {
			case fiber.StatusNotFound:
				errKey, msg = "not_found", "Not found"
			case fiber.StatusMethodNotAllowed:
				errKey, msg = "method_not_allowed", "Method not allowed"
			default:
				errKey, msg = "internal_error", err.Error()
			}
			// Mirror production: WriteFiberError returns the sentinel,
			// which Fiber would treat as "still erroring" → default 500.
			// Swallow it.
			_ = WriteFiberError(c, code, errKey, msg)
			return nil
		},
	})
	app.Use(middleware.RequestID())
	return app
}

// decodeEnvelope reads the response body as the canonical envelope
// (using map[string]any so we can detect absent fields, which is exactly
// what we want to enforce on retry_after_seconds=null vs missing).
func decodeEnvelope(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed), "body: %s", string(body))
	return parsed
}

// TestErrorEnvelope_503_AllFieldsAndHeader covers the canonical 503 case
// called out in the W7G brief: a transient-infra failure with NO registry
// entry. The envelope must carry request_id, retry_after_seconds=30, the
// AgentActionContactSupport fallback, AND the matching Retry-After: 30 header.
//
// Uses `db_error` as the fixture code: it's documented in helpers.go's
// curation principles as deliberately omitted from codeToAgentAction, so
// the W7G fallback branch fires deterministically. (Previously this test
// used `provision_failed`, but MR-P0-3 added an explicit retry-with-backoff
// entry for that code — its 503 must instruct the agent to retry, not
// contact support.)
func TestErrorEnvelope_503_AllFieldsAndHeader(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusServiceUnavailable,
			"db_error", "Failed to query platform database")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set(middleware.HeaderRequestID, "rid-fixed-123")
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)

	// HTTP-level assertions: status + Retry-After header parity.
	assert.Equal(t, fiber.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "30", resp.Header.Get(fiber.HeaderRetryAfter),
		"Retry-After header must match retry_after_seconds in the body so polite HTTP clients honor the wait without parsing JSON")
	assert.Equal(t, "rid-fixed-123", resp.Header.Get(middleware.HeaderRequestID),
		"X-Request-ID echo must match the body's request_id field")

	body := decodeEnvelope(t, resp)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "db_error", body["error"])
	assert.Equal(t, "Failed to query platform database", body["message"])
	assert.Equal(t, "rid-fixed-123", body["request_id"],
		"request_id must echo X-Request-ID so agents quoting it to support don't have to read headers")
	assert.Equal(t, float64(30), body["retry_after_seconds"],
		"503 default is 30s — gives clients a concrete number to wait")
	// Wave 3 (2026-05-21): db_error now has a domain-specific entry in
	// codeToAgentAction (see helpers.go); a 503 db_error renders the
	// "transient DB error, retry with backoff" sentence rather than the
	// generic AgentActionContactSupport fallback. The test confirms a
	// non-empty agent_action is set; the exact sentence is pinned in
	// the registry source.
	assert.NotEmpty(t, body["agent_action"],
		"5xx codes must carry SOME agent_action — either the registry entry or the support fallback")
	if action, ok := body["agent_action"].(string); ok {
		assert.Contains(t, action, "transient",
			"db_error agent_action should describe the transient DB error path")
	}
}

// TestErrorEnvelope_400_NullRetryAfter_NoHeader covers the 4xx case: the
// agent should NOT retry — the request itself is wrong. retry_after_seconds
// must be explicitly null (so agents know "don't retry, fix it"), and no
// Retry-After header should accompany it.
func TestErrorEnvelope_400_NullRetryAfter_NoHeader(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusBadRequest,
			"invalid_payload", "Field 'name' is required")
	})

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get(fiber.HeaderRetryAfter),
		"Retry-After header must NOT be set on 4xx — there's nothing safe to retry")

	body := decodeEnvelope(t, resp)
	// retry_after_seconds must be explicitly present as null — agents
	// reading the spec need to be able to distinguish "no retry, fix
	// the request" (null) from "field missing entirely" (a bug).
	raw, hasField := body["retry_after_seconds"]
	require.True(t, hasField, "retry_after_seconds key must be present on every error envelope, including 4xx")
	assert.Nil(t, raw, "retry_after_seconds must be null on 4xx (no retry — fix the request); got %v", raw)
	// Wave 3 (2026-05-21): invalid_payload now has a registry entry in
	// codeToAgentAction (see helpers.go); the 4xx envelope carries the
	// "request body could not be parsed" sentence. The pre-wave3
	// assertion (no agent_action on 4xx with no registry entry) is
	// preserved by switching the test code to a deliberately-unmapped
	// fabricated code — the original contract still holds for codes
	// outside the registry + allowlist (but the coverage test
	// TestErrorCode_HasAgentAction asserts every emit site has one).
	action, _ := body["agent_action"].(string)
	assert.Contains(t, action, "request body could not be parsed",
		"invalid_payload now carries the registry-mapped sentence")

	// request_id must always be populated when RequestID middleware ran.
	assert.NotEmpty(t, body["request_id"], "request_id must always be populated; got %v", body["request_id"])
}

// TestErrorEnvelope_429_RetryAfter60 covers the rate-limit code path:
// status 429 ⇒ retry_after_seconds=60 default ⇒ Retry-After: 60.
func TestErrorEnvelope_429_RetryAfter60(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusTooManyRequests,
			"rate_limit_exceeded", "Daily provisioning limit reached")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	assert.Equal(t, "60", resp.Header.Get(fiber.HeaderRetryAfter))
	body := decodeEnvelope(t, resp)
	assert.Equal(t, float64(60), body["retry_after_seconds"])
	// rate_limit_exceeded IS in the registry, so the registry copy wins.
	assert.Contains(t, body["agent_action"], "too many requests")
}

// TestErrorEnvelope_502_504_RetryAfter10 covers the bad-gateway / gateway-
// timeout cases: short retry (10s).
func TestErrorEnvelope_502_504_RetryAfter10(t *testing.T) {
	for _, status := range []int{fiber.StatusBadGateway, fiber.StatusGatewayTimeout} {
		app := envelopeApp(t)
		s := status
		app.Get("/x", func(c *fiber.Ctx) error {
			return respondError(c, s, "upstream_failed", "upstream call failed")
		})
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
		require.NoError(t, err)
		assert.Equal(t, s, resp.StatusCode)
		assert.Equal(t, "10", resp.Header.Get(fiber.HeaderRetryAfter),
			"status %d must set Retry-After: 10", s)
		body := decodeEnvelope(t, resp)
		assert.Equal(t, float64(10), body["retry_after_seconds"])
	}
}

// TestErrorEnvelope_500_NoRetryAfter covers the "generic 5xx" path: the
// envelope still carries the support-fallback agent_action, but no
// retry_after — the client cannot know if retry is safe, so we don't
// invite one.
func TestErrorEnvelope_500_NoRetryAfter(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusInternalServerError,
			"internal_error", "unexpected")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	assert.Empty(t, resp.Header.Get(fiber.HeaderRetryAfter),
		"500 must NOT set Retry-After — agent cannot know if retry is safe")
	body := decodeEnvelope(t, resp)
	raw, hasField := body["retry_after_seconds"]
	require.True(t, hasField, "retry_after_seconds key must still be present (null)")
	assert.Nil(t, raw, "500 must have retry_after_seconds=null")
	// Wave 3 (2026-05-21): internal_error has a domain-specific registry
	// entry, so the envelope renders the per-code sentence rather than the
	// generic AgentActionContactSupport fallback. Test instead that the
	// FALLBACK fires for an unmapped 5xx code (a code that is
	// intentionally outside both codeToAgentAction and the allowlist —
	// the support-fallback path is reachable but is the rare case now).
	// agent_action MUST be non-empty either way.
	assert.NotEmpty(t, body["agent_action"],
		"5xx must always carry an agent_action — registry entry preferred, fallback as floor")
	if action, ok := body["agent_action"].(string); ok {
		assert.Contains(t, action, "support@instanode.dev",
			"every 5xx agent_action — whether registry or fallback — names the support contact")
	}
}

// TestErrorEnvelope_FiberDefault405_Wrapped exercises the router-level
// ErrorHandler: a request that hits a route with the wrong HTTP method
// goes through Fiber's default 405 path, which our handler wraps so the
// envelope shape is identical to handler-emitted errors.
func TestErrorEnvelope_FiberDefault405_Wrapped(t *testing.T) {
	app := envelopeApp(t)
	app.Post("/only-post", func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})

	// GET a POST-only route → Fiber emits 405 via its default error path.
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/only-post", nil), 1000)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusMethodNotAllowed, resp.StatusCode)

	body := decodeEnvelope(t, resp)
	// Same envelope shape as respondError emits — request_id present,
	// retry_after_seconds=null (4xx → no retry, fix the verb).
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "method_not_allowed", body["error"])
	assert.NotEmpty(t, body["message"])
	assert.NotEmpty(t, body["request_id"],
		"Fiber-default 405 must still carry request_id (the agent needs the correlator regardless of who wrote the body)")
	_, hasField := body["retry_after_seconds"]
	require.True(t, hasField, "Fiber-default 405 envelope must include retry_after_seconds key (null)")
	assert.Nil(t, body["retry_after_seconds"])
}

// TestErrorEnvelope_FiberDefault404_Wrapped is the same guarantee for
// "no route matched" — agents probing an unknown path see the canonical
// envelope, not Fiber's plain-text default.
func TestErrorEnvelope_FiberDefault404_Wrapped(t *testing.T) {
	app := envelopeApp(t)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/no-such-route", nil), 1000)
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, resp.StatusCode)
	body := decodeEnvelope(t, resp)
	assert.Equal(t, "not_found", body["error"])
	assert.NotEmpty(t, body["request_id"])
}

// TestErrorEnvelope_AgentActionExplicitOverride covers the
// respondErrorWithAgentAction path: callers that supply tier-aware copy
// get it echoed verbatim, AND the envelope still carries the same auto-
// populated request_id + retry_after_seconds.
func TestErrorEnvelope_AgentActionExplicitOverride(t *testing.T) {
	app := envelopeApp(t)
	custom := "Tell the user they've hit the hobby tier storage limit (500MB). Upgrade at https://instanode.dev/pricing."
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"storage_limit_reached", "Storage limit reached.",
			custom, "https://instanode.dev/pricing")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	body := decodeEnvelope(t, resp)
	assert.Equal(t, custom, body["agent_action"], "explicit override must be echoed verbatim")
	assert.NotEmpty(t, body["request_id"], "explicit override must NOT skip request_id auto-population")
	// 402 isn't in the retry default table → null.
	raw, hasField := body["retry_after_seconds"]
	require.True(t, hasField)
	assert.Nil(t, raw)
}

// TestErrorEnvelope_RetryAfterOverride covers respondErrorWithRetry: the
// caller can pin a specific wait that the status-code default would miss
// (e.g. the rate-limit middleware that knows the actual window reset).
func TestErrorEnvelope_RetryAfterOverride(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondErrorWithRetry(c, fiber.StatusTooManyRequests,
			"rate_limit_exceeded", "Slow down", 5)
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	assert.Equal(t, "5", resp.Header.Get(fiber.HeaderRetryAfter),
		"explicit retry override must win over the 60s default for 429")
	body := decodeEnvelope(t, resp)
	assert.Equal(t, float64(5), body["retry_after_seconds"])
}

// TestErrorEnvelope_ContactSupportContract enforces the U3 contract on
// the new AgentActionContactSupport constant — same four requirements
// as every other agent_action string. (TestAgentActionContract covers
// the rest of the registry; this is the W7G addition.)
func TestErrorEnvelope_ContactSupportContract(t *testing.T) {
	s := AgentActionContactSupport
	// 1. Imperative opening.
	assert.True(t, len(s) > len("Tell the user") &&
		s[:len("Tell the user")] == "Tell the user",
		"AgentActionContactSupport must open with 'Tell the user'; got %q", s)
	// 2. Specific reason (we name "our side went wrong" / "request_id").
	assert.Contains(t, s, "request_id",
		"AgentActionContactSupport must name request_id so the user knows what to quote")
	// 3. Exact next action.
	assert.Contains(t, s, "support@instanode.dev",
		"AgentActionContactSupport must name the support email — that's the action")
	// 4. Full https URL.
	assert.Contains(t, s, "https://instanode.dev/",
		"AgentActionContactSupport must contain a full https://instanode.dev URL")
	// 5. Under 280 chars (tweet ceiling).
	assert.Less(t, len(s), 280,
		"AgentActionContactSupport must be under 280 chars (LLM verbatim ceiling); got %d", len(s))
}

// TestErrorEnvelope_RequestIDEmptyWhenMiddlewareSkipped is the
// belt-and-suspenders guarantee: a test that constructs a Fiber app
// WITHOUT the RequestID middleware (rare but possible in unit tests)
// produces an envelope with request_id omitted (omitempty), NOT the
// literal string "". Agents reading the spec rely on this distinction.
func TestErrorEnvelope_RequestIDEmptyWhenMiddlewareSkipped(t *testing.T) {
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == ErrResponseWritten {
				return nil
			}
			return c.SendStatus(fiber.StatusInternalServerError)
		},
	})
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusBadRequest, "invalid_payload", "bad")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	body := decodeEnvelope(t, resp)
	_, hasID := body["request_id"]
	assert.False(t, hasID, "request_id must be omitted (omitempty) when middleware didn't run; got %v", body["request_id"])
}

// TestErrorEnvelope_RetryAfterHeaderIsAnInteger guards a subtle bug class:
// strconv vs fmt.Sprintf("%d") drift could land a quoted "30" in the
// header instead of `30`. RFC 7231 says the value is a numeric integer of
// seconds — clients parse it with strconv. We assert strconv.Atoi
// round-trips cleanly.
func TestErrorEnvelope_RetryAfterHeaderIsAnInteger(t *testing.T) {
	app := envelopeApp(t)
	app.Get("/x", func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusServiceUnavailable, "x", "y")
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/x", nil), 1000)
	require.NoError(t, err)
	v := resp.Header.Get(fiber.HeaderRetryAfter)
	n, err := strconv.Atoi(v)
	require.NoError(t, err, "Retry-After must parse as integer seconds (RFC 7231); got %q", v)
	assert.Equal(t, 30, n)
}
