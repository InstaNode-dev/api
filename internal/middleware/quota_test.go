package middleware_test

// quota_test.go — exercises middleware.PaymentRequired, the helper that
// emits HTTP 402 with a Stripe Machine Payments Protocol-compatible
// WWW-Authenticate header when a quota check fails.

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

	"instant.dev/internal/middleware"
)

// Test402_QuotaExceeded verifies that PaymentRequired returns 402 with the
// canonical body shape and WWW-Authenticate: Payment header.
func Test402_QuotaExceeded(t *testing.T) {
	app := fiber.New()
	app.Post("/db/new", func(c *fiber.Ctx) error {
		return middleware.PaymentRequired(c, "")
	})

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.True(t, strings.HasPrefix(wwwAuth, "Payment "),
		"WWW-Authenticate must start with `Payment ` keyword (got %q)", wwwAuth)
	assert.Contains(t, wwwAuth, `realm="instanode"`)
	assert.Contains(t, wwwAuth, `upgrade_url="`+middleware.QuotaUpgradeURL+`"`)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Equal(t, false, parsed["ok"])
	assert.Equal(t, "quota_exceeded", parsed["error"])
	assert.Equal(t, middleware.QuotaUpgradeURL, parsed["upgrade_url"])
}

// Test402_CustomErrorKey verifies the helper accepts a custom error keyword
// (e.g. "storage_exceeded", "throughput_exceeded") for distinct quota classes.
func Test402_CustomErrorKey(t *testing.T) {
	app := fiber.New()
	app.Post("/db/new", func(c *fiber.Ctx) error {
		return middleware.PaymentRequired(c, "storage_exceeded")
	})

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	_ = json.Unmarshal(body, &parsed)
	assert.Equal(t, "storage_exceeded", parsed["error"])
}

// Test402_IncludesAgentAction guards RETRO-2026-05-12 §10.15: the 402
// quota wall response must carry an agent_action sentence the calling
// agent can show the user without inventing prose. Without this, an
// agent hitting "quota exceeded" has to guess what to say — the whole
// point of the spec is to make the API self-narrating.
func Test402_IncludesAgentAction(t *testing.T) {
	app := fiber.New()
	app.Post("/db/new", func(c *fiber.Ctx) error {
		return middleware.PaymentRequired(c, "")
	})

	req := httptest.NewRequest(http.MethodPost, "/db/new", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(body, &parsed))

	action, ok := parsed["agent_action"].(string)
	require.True(t, ok, "agent_action must be a string field on 402 responses")
	assert.NotEmpty(t, action, "agent_action must be populated on quota walls")
	assert.Contains(t, strings.ToLower(action), "plan",
		"agent_action must reference 'plan' so the agent's prose reads naturally")
	assert.Contains(t, action, middleware.QuotaUpgradeURL,
		"agent_action must reference the upgrade_url so the agent can paste the link inline")
}
