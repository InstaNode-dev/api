package handlers

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOpenAPISpecParses ensures the embedded OpenAPI spec is valid JSON. Any
// stray backtick or escape mistake in a description string causes the spec
// to fail JSON parse, which produces a useless 500 at /openapi.json.
func TestOpenAPISpecParses(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec is not valid JSON: %v", err)
	}
	if v["openapi"] != "3.1.0" {
		t.Errorf("openapi version = %v; want 3.1.0", v["openapi"])
	}
}

// TestOpenAPI_DeployRequestHasEnvVars guards the contract addition for friction
// fix #11 (env vars in initial POST /deploy/new).
func TestOpenAPI_DeployRequestHasEnvVars(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "DeployRequest", "properties")
	if !ok {
		t.Fatal("could not navigate to DeployRequest.properties in spec")
	}
	if _, ok := props["env_vars"]; !ok {
		t.Error("DeployRequest.properties.env_vars is missing — agents have no machine-readable signal that env can be set on initial POST")
	}
}

// TestOpenAPI_BearerAuthDocumentsClaimFlow guards the contract addition for
// friction fix #2 (auth flow must be discoverable via OpenAPI).
func TestOpenAPI_BearerAuthDocumentsClaimFlow(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	bearer, ok := digMap(v, "components", "securitySchemes", "bearerAuth")
	if !ok {
		t.Fatal("could not navigate to bearerAuth in spec")
	}
	desc, _ := bearer["description"].(string)
	for _, must := range []string{"/claim", "anonymous", "api-keys"} {
		if !strings.Contains(desc, must) {
			t.Errorf("bearerAuth.description must mention %q so an agent reading the OpenAPI alone can discover the auth flow; got: %s", must, desc)
		}
	}
}

// TestOpenAPI_ClaimPreviewEndpointDocumented guards friction #15: the
// /claim/preview probe was implemented but undocumented, so agents had no
// machine-readable signal that they could surface "what will I claim?" to
// the user before they enter their email.
func TestOpenAPI_ClaimPreviewEndpointDocumented(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, _ := v["paths"].(map[string]any)
	if _, ok := paths["/claim/preview"].(map[string]any); !ok {
		t.Error("/claim/preview is missing from OpenAPI paths — agents cannot discover the no-side-effect probe of claimable resources")
	}
	if props, ok := digMap(v, "components", "schemas", "ClaimPreviewResponse", "properties"); ok {
		for _, k := range []string{"ok", "token_valid", "resources", "expires_at"} {
			if _, ok := props[k]; !ok {
				t.Errorf("ClaimPreviewResponse.properties.%s missing", k)
			}
		}
	} else {
		t.Error("ClaimPreviewResponse schema missing")
	}
}

// TestOpenAPI_ClaimRequestDocumentsUpgradeJWT guards friction #16 — the
// ClaimRequest doc must point agents at the upgrade_jwt response field
// rather than telling them to string-strip the upgrade URL.
func TestOpenAPI_ClaimRequestDocumentsUpgradeJWT(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "ClaimRequest", "properties")
	if !ok {
		t.Fatal("ClaimRequest schema missing")
	}
	jwt, _ := props["jwt"].(map[string]any)
	desc, _ := jwt["description"].(string)
	if !strings.Contains(desc, "upgrade_jwt") {
		t.Errorf("ClaimRequest.jwt description must mention the upgrade_jwt response field; got: %s", desc)
	}
}

// TestOpenAPI_StacksEndpointsDocumented guards friction #1 — /stacks/new was
// already implemented but undocumented, so agents reading the spec had no way
// to discover the multi-service deploy primitive. This test ensures the path
// stays in the spec and a future cleanup doesn't accidentally drop it.
func TestOpenAPI_StacksEndpointsDocumented(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, _ := v["paths"].(map[string]any)
	for _, p := range []string{"/stacks/new", "/stacks/{slug}", "/stacks/{slug}/redeploy"} {
		if _, ok := paths[p].(map[string]any); !ok {
			t.Errorf("OpenAPI is missing path %q — agents cannot discover the multi-service deploy primitive from the spec alone", p)
		}
	}
	// StackResponse schema must describe the array-of-services shape so agents
	// know how to read the status of each service after deploy.
	if props, ok := digMap(v, "components", "schemas", "StackResponse", "properties"); ok {
		if _, ok := props["services"]; !ok {
			t.Error("StackResponse schema missing 'services' field — agents have no machine-readable signal that per-service status is reported as an array")
		}
	} else {
		t.Error("StackResponse schema missing entirely")
	}
}

func digMap(root map[string]any, keys ...string) (map[string]any, bool) {
	cur := root
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}
