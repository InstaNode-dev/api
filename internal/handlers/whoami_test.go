package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOpenAPI_WhoamiPathExists guards the friction-fix contract: an agent
// reading openapi.json must find /api/v1/whoami so it has a canonical
// "am I authenticated?" probe.
func TestOpenAPI_WhoamiPathExists(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, ok := v["paths"].(map[string]any)
	if !ok {
		t.Fatal("openAPISpec has no paths object")
	}
	whoami, ok := paths["/api/v1/whoami"].(map[string]any)
	if !ok {
		t.Fatal("/api/v1/whoami missing from OpenAPI paths")
	}
	get, ok := whoami["get"].(map[string]any)
	if !ok {
		t.Fatal("/api/v1/whoami has no GET operation")
	}
	if sec, _ := get["security"].([]any); len(sec) == 0 {
		t.Error("/api/v1/whoami must declare bearerAuth so agents know auth is required")
	}
	responses, _ := get["responses"].(map[string]any)
	if _, ok := responses["401"]; !ok {
		t.Error("/api/v1/whoami must document 401 — the whole point is to return 401 on bad tokens")
	}
}

// TestOpenAPI_WhoamiResponseSchema guards that the schema documents the
// fields an agent needs (user_id, team_id, plan_tier).
func TestOpenAPI_WhoamiResponseSchema(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "WhoamiResponse", "properties")
	if !ok {
		t.Fatal("WhoamiResponse schema missing from components")
	}
	for _, key := range []string{"ok", "user_id", "team_id", "plan_tier"} {
		if _, ok := props[key]; !ok {
			t.Errorf("WhoamiResponse.properties.%s missing — agent loses the signal it relies on", key)
		}
	}
	// Description on plan_tier should hint that it may be absent.
	if tier, ok := props["plan_tier"].(map[string]any); ok {
		if desc, _ := tier["description"].(string); !strings.Contains(strings.ToLower(desc), "absent") && !strings.Contains(strings.ToLower(desc), "best-effort") {
			t.Errorf("plan_tier description should warn that it can be absent on DB failure; got %q", desc)
		}
	}
}
