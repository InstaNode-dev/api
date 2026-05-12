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

// TestOpenAPI_MultiEnvEndpointsDocumented guards RETRO-2026-05-12 §10.17:
// the env-promotion endpoints (POST /api/v1/stacks/:slug/promote and
// POST /api/v1/vault/copy) must be discoverable in the spec, and both must
// document the 402 upgrade_required response so agents know the tier gate
// exists and what error code to expect on free / hobby tiers.
func TestOpenAPI_MultiEnvEndpointsDocumented(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, _ := v["paths"].(map[string]any)
	for _, p := range []string{
		"/api/v1/stacks/{slug}/promote",
		"/api/v1/vault/copy",
	} {
		op, ok := paths[p].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI is missing path %q — agents cannot discover the multi-env workflow endpoints", p)
			continue
		}
		post, ok := op["post"].(map[string]any)
		if !ok {
			t.Errorf("path %q missing POST operation", p)
			continue
		}
		responses, _ := post["responses"].(map[string]any)
		if _, ok := responses["402"]; !ok {
			t.Errorf("path %q must document the 402 upgrade_required response — agents need to know the tier gate exists", p)
		}
	}
}

// TestOpenAPI_ErrorResponseSchemaDocumented guards RETRO-2026-05-12 §10.15:
// the canonical ErrorResponse schema (with agent_action and upgrade_url)
// must be discoverable in the spec, and the agent-relevant provisioning
// endpoints must reference it on 4xx/5xx responses so agents reading the
// spec alone know to expect agent_action copy.
func TestOpenAPI_ErrorResponseSchemaDocumented(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	schema, ok := digMap(v, "components", "schemas", "ErrorResponse")
	if !ok {
		t.Fatal("components.schemas.ErrorResponse missing — agents cannot discover the canonical error shape")
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("ErrorResponse.properties missing")
	}
	for _, k := range []string{"ok", "error", "message", "agent_action", "upgrade_url"} {
		if _, ok := props[k]; !ok {
			t.Errorf("ErrorResponse.properties.%s missing — agents need this field documented to know it's optional and what to do with it", k)
		}
	}
	// The description must teach agents what agent_action means — otherwise
	// they'll ignore it the same way they'd ignore any unknown field.
	actionDesc, _ := props["agent_action"].(map[string]any)
	desc, _ := actionDesc["description"].(string)
	if !strings.Contains(strings.ToLower(desc), "agent") || !strings.Contains(strings.ToLower(desc), "user") {
		t.Errorf("ErrorResponse.properties.agent_action.description should explain it's a sentence the agent shows the user; got: %s", desc)
	}

	// Provisioning endpoints must reference ErrorResponse on 402 so agents
	// reading the spec know agent_action is on the wire for quota walls.
	paths, _ := v["paths"].(map[string]any)
	for _, p := range []string{"/db/new", "/cache/new", "/nosql/new", "/queue/new", "/storage/new"} {
		ep, ok := paths[p].(map[string]any)
		if !ok {
			continue // some envs may not register a path; that's a different test's concern
		}
		post, ok := ep["post"].(map[string]any)
		if !ok {
			continue
		}
		responses, _ := post["responses"].(map[string]any)
		r402, ok := responses["402"].(map[string]any)
		if !ok {
			t.Errorf("%s POST must document a 402 response with ErrorResponse so agents know to expect agent_action on quota walls", p)
			continue
		}
		body, _ := digMap(r402, "content", "application/json")
		schemaRef, _ := body["schema"].(map[string]any)
		ref, _ := schemaRef["$ref"].(string)
		if !strings.HasSuffix(ref, "/ErrorResponse") {
			t.Errorf("%s 402 should $ref ErrorResponse; got %q", p, ref)
		}
	}
}

// TestOpenAPI_CachedAggregateEndpointsDocumented guards Wave 4-L: the two
// cached aggregate endpoints (/api/v1/billing/usage and /api/v1/team/summary)
// are live and tested in production but were undocumented in the OpenAPI
// spec until this fix. Agents reading /openapi.json alone now have a
// machine-readable signal that the cached aggregates exist + what their
// payload shapes look like, so they can pull dashboard-style metrics
// without falling back to scanning the full /resources list.
func TestOpenAPI_CachedAggregateEndpointsDocumented(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, _ := v["paths"].(map[string]any)
	for _, p := range []string{
		"/api/v1/billing/usage",
		"/api/v1/team/summary",
	} {
		op, ok := paths[p].(map[string]any)
		if !ok {
			t.Errorf("OpenAPI is missing path %q — agents cannot discover the cached aggregate endpoints", p)
			continue
		}
		get, ok := op["get"].(map[string]any)
		if !ok {
			t.Errorf("path %q missing GET operation", p)
			continue
		}
		// Both endpoints are session-gated; if bearerAuth gets dropped from
		// the security stanza, a dashboard refactor probably ripped the auth
		// requirement out by accident.
		sec, _ := get["security"].([]any)
		if len(sec) == 0 {
			t.Errorf("path %q GET must declare bearerAuth — these endpoints require a session JWT", p)
		}
		// 200 response must reference a schema and document the Cache-Control
		// header — that's the whole point of these endpoints, and an agent
		// reading the spec needs to know they're cache-friendly.
		responses, _ := get["responses"].(map[string]any)
		r200, ok := responses["200"].(map[string]any)
		if !ok {
			t.Errorf("path %q must document a 200 response with the cached payload schema", p)
			continue
		}
		headers, _ := r200["headers"].(map[string]any)
		if _, ok := headers["Cache-Control"].(map[string]any); !ok {
			t.Errorf("path %q 200 response must document the Cache-Control header so agents know the response is cacheable", p)
		}
		body, _ := digMap(r200, "content", "application/json")
		schemaRef, _ := body["schema"].(map[string]any)
		ref, _ := schemaRef["$ref"].(string)
		if ref == "" {
			t.Errorf("path %q 200 must $ref a response schema", p)
		}
	}

	// Schemas must be present + carry the canonical aggregate fields.
	if props, ok := digMap(v, "components", "schemas", "BillingUsageResponse", "properties"); ok {
		for _, k := range []string{"ok", "freshness_seconds", "as_of", "usage"} {
			if _, ok := props[k]; !ok {
				t.Errorf("BillingUsageResponse.properties.%s missing — agents lose the cache-window contract", k)
			}
		}
	} else {
		t.Error("components.schemas.BillingUsageResponse missing")
	}
	if props, ok := digMap(v, "components", "schemas", "TeamSummaryResponse", "properties"); ok {
		for _, k := range []string{"ok", "freshness_seconds", "as_of", "tier", "counts"} {
			if _, ok := props[k]; !ok {
				t.Errorf("TeamSummaryResponse.properties.%s missing — agents lose the cache-window contract", k)
			}
		}
	} else {
		t.Error("components.schemas.TeamSummaryResponse missing")
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
