package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// TestWellKnown_Spec asserts that GET /.well-known/oauth-protected-resource
// returns a JSON document conforming to the MCP authorization profile.
//
// Required fields per the MCP draft (mirrors RFC 9728):
//   - resource (string)
//   - authorization_servers ([]string)
//   - bearer_methods_supported ([]string, must include "header")
//   - resource_documentation (string)
func TestWellKnown_Spec(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "https://api.instanode.dev")

	app := fiber.New()
	app.Get("/.well-known/oauth-protected-resource", handlers.ServeOAuthProtectedResourceMetadata)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)

	assert.Equal(t, "https://api.instanode.dev", body["resource"])

	servers, ok := body["authorization_servers"].([]any)
	require.True(t, ok, "authorization_servers must be an array")
	require.Len(t, servers, 1)
	assert.Equal(t, "https://api.instanode.dev", servers[0])

	methods, ok := body["bearer_methods_supported"].([]any)
	require.True(t, ok, "bearer_methods_supported must be an array")
	assert.Contains(t, methods, "header")

	assert.Equal(t, "https://instanode.dev/docs/auth", body["resource_documentation"])
}

// TestWellKnown_FallsBackToRequestHost verifies that when API_PUBLIC_URL is unset
// the canonical URL is derived from the live request (Host header + scheme).
func TestWellKnown_FallsBackToRequestHost(t *testing.T) {
	t.Setenv("API_PUBLIC_URL", "")

	app := fiber.New()
	app.Get("/.well-known/oauth-protected-resource", handlers.ServeOAuthProtectedResourceMetadata)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	req.Host = "api.example.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := app.Test(req, 1000)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body map[string]any
	testhelpers.DecodeJSON(t, resp, &body)

	resource, _ := body["resource"].(string)
	assert.Equal(t, "https://api.example.test", resource)
}
