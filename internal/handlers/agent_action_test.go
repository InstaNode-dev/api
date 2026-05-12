package handlers

// agent_action_test.go — covers RETRO-2026-05-12 §10.15: every 4xx/5xx
// response from a handler that hits a quota wall, invalid token, expired
// resource, permission denied, or tier gate must carry an `agent_action`
// field (and `upgrade_url` when relevant) so the calling agent can show
// the user actionable copy without inventing prose.
//
// Two layers are tested:
//
//   1. respondError + respondErrorWithAgentAction — the helpers themselves.
//      Direct table-driven tests against a tiny Fiber app guarantee the
//      JSON shape is correct, agent_action is populated from the registry
//      for known codes, omitted for unknown ones, and tier-aware overrides
//      win over registry defaults.
//
//   2. Backward compatibility — omitempty must hide the new fields when
//      they're empty so existing clients (dashboard, MCP, CLI) that ignore
//      them see no change on the wire.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: do a one-shot Fiber request and decode the JSON body into the
// canonical error response shape (using a map so we can detect absent
// fields, which is exactly what omitempty needs to be verified against).
func doErrorRequest(t *testing.T, handler fiber.Handler) (int, map[string]any) {
	t.Helper()
	app := fiber.New(fiber.Config{
		// Mimic the production / test ErrorHandler: respondError already
		// wrote the body, so we must short-circuit on ErrResponseWritten.
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == ErrResponseWritten {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok":      false,
				"error":   "internal_error",
				"message": err.Error(),
			})
		},
	})
	app.Get("/x", handler)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	return resp.StatusCode, parsed
}

// TestRespondError_KnownCode_PopulatesAgentAction verifies that codes
// present in codeToAgentAction emit agent_action (and upgrade_url for
// quota walls) on the wire.
func TestRespondError_KnownCode_PopulatesAgentAction(t *testing.T) {
	cases := []struct {
		name             string
		code             string
		status           int
		wantUpgradeURL   bool
		wantActionSubstr string
	}{
		{
			name:             "quota_exceeded gets upgrade_url + 'plan' copy",
			code:             "quota_exceeded",
			status:           fiber.StatusPaymentRequired,
			wantUpgradeURL:   true,
			wantActionSubstr: "plan's usage limit",
		},
		{
			name:             "storage_limit_reached gets upgrade_url",
			code:             "storage_limit_reached",
			status:           fiber.StatusPaymentRequired,
			wantUpgradeURL:   true,
			wantActionSubstr: "storage limit",
		},
		{
			name:             "vault_quota_exceeded gets upgrade_url",
			code:             "vault_quota_exceeded",
			status:           fiber.StatusPaymentRequired,
			wantUpgradeURL:   true,
			wantActionSubstr: "vault entry quota",
		},
		{
			name:             "upgrade_required gets upgrade_url",
			code:             "upgrade_required",
			status:           fiber.StatusPaymentRequired,
			wantUpgradeURL:   true,
			wantActionSubstr: "higher plan",
		},
		{
			name:             "rate_limit_exceeded gets upgrade_url",
			code:             "rate_limit_exceeded",
			status:           fiber.StatusTooManyRequests,
			wantUpgradeURL:   true,
			wantActionSubstr: "too many requests",
		},
		{
			name:             "invalid_token points at login, no upgrade_url",
			code:             "invalid_token",
			status:           fiber.StatusBadRequest,
			wantUpgradeURL:   false,
			wantActionSubstr: "log in at https://instanode.dev/login",
		},
		{
			name:             "unauthorized points at login",
			code:             "unauthorized",
			status:           fiber.StatusUnauthorized,
			wantUpgradeURL:   false,
			wantActionSubstr: "log in at https://instanode.dev/login",
		},
		{
			name:             "auth_required points at login/signup",
			code:             "auth_required",
			status:           fiber.StatusPaymentRequired,
			wantUpgradeURL:   false,
			wantActionSubstr: "log in at https://instanode.dev/login",
		},
		{
			name:             "webhook_inactive tells agent to re-provision",
			code:             "webhook_inactive",
			status:           fiber.StatusGone,
			wantUpgradeURL:   false,
			wantActionSubstr: "POST /webhook/new",
		},
		{
			name:             "forbidden suggests checking team membership",
			code:             "forbidden",
			status:           fiber.StatusForbidden,
			wantUpgradeURL:   false,
			wantActionSubstr: "permission",
		},
		{
			name:             "vault_requires_auth points at login",
			code:             "vault_requires_auth",
			status:           fiber.StatusUnauthorized,
			wantUpgradeURL:   false,
			wantActionSubstr: "log in",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body := doErrorRequest(t, func(c *fiber.Ctx) error {
				return respondError(c, tc.status, tc.code, "human message")
			})
			assert.Equal(t, tc.status, status, "status code")
			assert.Equal(t, false, body["ok"], "ok should be false")
			assert.Equal(t, tc.code, body["error"], "error code")
			assert.Equal(t, "human message", body["message"], "message preserved")
			action, _ := body["agent_action"].(string)
			require.NotEmpty(t, action, "agent_action must be populated for known code %q", tc.code)
			assert.Contains(t, strings.ToLower(action), strings.ToLower(tc.wantActionSubstr),
				"agent_action must mention %q for code %q", tc.wantActionSubstr, tc.code)
			if tc.wantUpgradeURL {
				assert.Equal(t, "https://instanode.dev/pricing", body["upgrade_url"],
					"upgrade_url must be present for quota/tier codes")
			} else {
				_, hasURL := body["upgrade_url"]
				assert.False(t, hasURL, "upgrade_url must be omitted (omitempty) for non-quota codes; got %v", body["upgrade_url"])
			}
		})
	}
}

// TestRespondError_UnknownCode_OmitsAgentAction guards the backward
// compatibility promise: codes not in the registry produce the historical
// 3-field shape, so existing clients (dashboard, MCP) that didn't know
// about agent_action keep working.
func TestRespondError_UnknownCode_OmitsAgentAction(t *testing.T) {
	status, body := doErrorRequest(t, func(c *fiber.Ctx) error {
		return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", "transient failure")
	})
	assert.Equal(t, fiber.StatusServiceUnavailable, status)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "provision_failed", body["error"])
	assert.Equal(t, "transient failure", body["message"])

	_, hasAction := body["agent_action"]
	assert.False(t, hasAction, "agent_action must be omitted for unknown codes; got %v", body["agent_action"])
	_, hasURL := body["upgrade_url"]
	assert.False(t, hasURL, "upgrade_url must be omitted for unknown codes; got %v", body["upgrade_url"])
}

// TestRespondErrorWithAgentAction_Override verifies that callers can pass
// a tier-aware agent_action (e.g. naming the specific tier or limit) and
// have it appear on the wire instead of the registry default.
func TestRespondErrorWithAgentAction_Override(t *testing.T) {
	custom := "Tell the user they've hit the hobby tier storage limit (500MB). Have them upgrade at https://instanode.dev/pricing to provision more storage."
	status, body := doErrorRequest(t, func(c *fiber.Ctx) error {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"storage_limit_reached",
			"Storage limit reached (500MB). Upgrade your plan.",
			custom,
			"https://instanode.dev/pricing")
	})
	assert.Equal(t, fiber.StatusPaymentRequired, status)
	assert.Equal(t, "storage_limit_reached", body["error"])
	assert.Equal(t, custom, body["agent_action"], "explicit agent_action must override registry default")
	assert.Equal(t, "https://instanode.dev/pricing", body["upgrade_url"])
	assert.Contains(t, body["agent_action"].(string), "hobby tier",
		"tier-aware override must mention the specific tier")
	assert.Contains(t, body["agent_action"].(string), "500MB",
		"tier-aware override must mention the specific limit")
}

// TestRespondErrorWithAgentAction_EmptyURL_Omitted verifies omitempty
// behaviour: a caller that supplies agent_action but no upgrade_url
// produces a response with the URL field absent on the wire.
func TestRespondErrorWithAgentAction_EmptyURL_Omitted(t *testing.T) {
	_, body := doErrorRequest(t, func(c *fiber.Ctx) error {
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			"invalid_token",
			"JWT is expired",
			"The user's token has expired. Have them log in at https://instanode.dev/login.",
			"")
	})
	assert.Equal(t, "invalid_token", body["error"])
	assert.NotEmpty(t, body["agent_action"])
	_, hasURL := body["upgrade_url"]
	assert.False(t, hasURL, "empty upgrade_url must be omitted via omitempty")
}

// TestErrorResponse_JSONShape_OmitemptyEnforced is the contract-level
// guarantee: ErrorResponse with empty AgentAction and UpgradeURL must
// marshal to exactly {"ok":false,"error":"x","message":"y"} — no extra
// keys. Dashboard / MCP clients that don't know about the new fields
// must see no change on the wire.
func TestErrorResponse_JSONShape_OmitemptyEnforced(t *testing.T) {
	raw, err := json.Marshal(ErrorResponse{
		OK:      false,
		Error:   "provision_failed",
		Message: "transient",
	})
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "agent_action",
		"agent_action must be omitted when empty; backward-compat would break otherwise")
	assert.NotContains(t, string(raw), "upgrade_url",
		"upgrade_url must be omitted when empty")
}

// TestErrorResponse_JSONShape_PopulatedFields ensures that when fields
// are present they marshal correctly and use the expected JSON keys
// (snake_case, matching the spec in §10.15).
func TestErrorResponse_JSONShape_PopulatedFields(t *testing.T) {
	raw, err := json.Marshal(ErrorResponse{
		OK:          false,
		Error:       "quota_exceeded",
		Message:     "Storage limit reached.",
		AgentAction: "Tell the user…",
		UpgradeURL:  "https://instanode.dev/pricing",
	})
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"agent_action":"Tell the user…"`)
	assert.Contains(t, string(raw), `"upgrade_url":"https://instanode.dev/pricing"`)
}

// TestRespondError_ReturnsErrResponseWritten guards the existing contract:
// respondError always returns the sentinel error so multi-return helpers
// short-circuit correctly. Spec §10.15 must not regress this.
func TestRespondError_ReturnsErrResponseWritten(t *testing.T) {
	app := fiber.New()
	var captured error
	app.Get("/x", func(c *fiber.Ctx) error {
		captured = respondError(c, fiber.StatusBadRequest, "invalid_token", "bad")
		return captured
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	_, err := app.Test(req, 1000)
	require.NoError(t, err)
	assert.ErrorIs(t, captured, ErrResponseWritten)
}
