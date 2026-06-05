package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
	// 2026-05-20: canonical field renamed jwt→token; legacy jwt remains as
	// deprecated alias. The "upgrade_jwt" cross-reference now lives on the
	// canonical (token) description so new callers reading the spec land on
	// the right field. The deprecated jwt description was intentionally
	// trimmed to discourage further use — checking it for "upgrade_jwt"
	// would re-anchor doc gravity to the deprecated field.
	tok, _ := props["token"].(map[string]any)
	tokDesc, _ := tok["description"].(string)
	if !strings.Contains(tokDesc, "upgrade_jwt") {
		t.Errorf("ClaimRequest.token description must mention the upgrade_jwt response field; got: %s", tokDesc)
	}
	// Verify the deprecated jwt field still exists (kept as alias) but
	// don't require it to repeat the upgrade_jwt cross-reference.
	if _, ok := props["jwt"].(map[string]any); !ok {
		t.Error("ClaimRequest.jwt (deprecated alias) must still be in the schema for backward compat")
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

// TestOpenAPI_StackRequestUsesAdditionalProperties pins DOG-30 (QA 2026-05-29):
// the dynamic per-service multipart field used to be modeled with a literal
// "<service-name>" property in the StackRequest schema, which codegen clients
// (Postman, OpenAPI-generator, etc.) would interpret as "a property literally
// named <service-name>", emitting broken upload code. The contract is now
// expressed with additionalProperties — the OpenAPI-3 idiom for "any
// additional field with this shape".
func TestOpenAPI_StackRequestUsesAdditionalProperties(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	schema, ok := digMap(v, "components", "schemas", "StackRequest")
	if !ok {
		t.Fatal("DOG-30: StackRequest schema missing entirely")
	}

	// The literal placeholder must NOT appear as a property — it's the
	// regression marker for the original bug. Codegen clients emitted a
	// real field literally named "<service-name>" when this was present.
	props, _ := schema["properties"].(map[string]any)
	if _, has := props["<service-name>"]; has {
		t.Error("DOG-30: StackRequest.properties still contains the literal '<service-name>' placeholder — codegen clients will emit a broken field with that literal name. Use additionalProperties to express the dynamic per-service shape instead.")
	}

	// additionalProperties must be present with the binary-upload shape so
	// codegen clients understand "for every service in manifest.services,
	// emit one upload field named after the service".
	ap, has := schema["additionalProperties"]
	if !has {
		t.Fatal("DOG-30: StackRequest schema missing additionalProperties — the dynamic per-service multipart field has no machine-readable contract")
	}
	apMap, ok := ap.(map[string]any)
	if !ok {
		t.Fatalf("DOG-30: StackRequest.additionalProperties must be an object schema, got %T", ap)
	}
	if apMap["type"] != "string" {
		t.Errorf("DOG-30: StackRequest.additionalProperties.type must be 'string' (multipart upload), got %v", apMap["type"])
	}
	if apMap["format"] != "binary" {
		t.Errorf("DOG-30: StackRequest.additionalProperties.format must be 'binary' (multipart binary upload), got %v", apMap["format"])
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
	// W7G envelope: ErrorResponse schema must document every standardized
	// field — including the three new ones (request_id, retry_after_seconds,
	// agent_action universal fallback). Agents reading openapi.json alone
	// must know to expect these on the wire.
	for _, k := range []string{"ok", "error", "message", "request_id", "retry_after_seconds", "agent_action", "upgrade_url"} {
		if _, ok := props[k]; !ok {
			t.Errorf("ErrorResponse.properties.%s missing — agents need this field documented to know it's optional and what to do with it", k)
		}
	}
	// retry_after_seconds must be marked required so the spec's
	// "null on 4xx, int on 5xx" contract is unambiguous — an agent
	// reading the JSON Schema should treat its absence as a server
	// bug, not a "feature unused on this response."
	required, _ := schema["required"].([]any)
	hasRetry := false
	for _, r := range required {
		if s, _ := r.(string); s == "retry_after_seconds" {
			hasRetry = true
			break
		}
	}
	if !hasRetry {
		t.Error("ErrorResponse.required must include retry_after_seconds — agents distinguish null (no retry) from missing (server bug)")
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

// TestOpenAPI_ServerURLIsCanonicalProduction guards Wave FIX-E #C1 — the
// servers[0].url was set to https://instant.dev (dead-brand, returns 404).
// An agent reading the OpenAPI to figure out where to send requests would
// land on a parking page and give up. Must be https://api.instanode.dev.
func TestOpenAPI_ServerURLIsCanonicalProduction(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	servers, ok := v["servers"].([]any)
	if !ok || len(servers) == 0 {
		t.Fatal("servers[] missing")
	}
	first, _ := servers[0].(map[string]any)
	url, _ := first["url"].(string)
	if url != "https://api.instanode.dev" {
		t.Errorf("servers[0].url = %q; want https://api.instanode.dev (dead-brand https://instant.dev 404s)", url)
	}
}

// TestOpenAPI_ResourceTypeEnumIsCanonical guards Wave FIX-E #C9 — the
// resource_type enum on both ResourceItem AND ClaimPreviewResponse drifted
// to ["postgres","redis","mongodb","nats","webhook","storage"]: the value
// "nats" was never written to the resources.resource_type column (handlers
// emit "queue"), and the column "vector" — shipped at /vector/new — was
// missing entirely. Both schemas must reference the canonical 7-value set.
func TestOpenAPI_ResourceTypeEnumIsCanonical(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	want := map[string]bool{
		"postgres": true, "redis": true, "mongodb": true,
		"queue": true, "storage": true, "webhook": true, "vector": true,
	}

	// ResourceItem
	props, ok := digMap(v, "components", "schemas", "ResourceItem", "properties")
	if !ok {
		t.Fatal("ResourceItem.properties missing")
	}
	rt, _ := props["resource_type"].(map[string]any)
	enumAny, _ := rt["enum"].([]any)
	got := map[string]bool{}
	for _, e := range enumAny {
		if s, _ := e.(string); s != "" {
			got[s] = true
		}
	}
	for w := range want {
		if !got[w] {
			t.Errorf("ResourceItem.resource_type.enum missing %q", w)
		}
	}
	if got["nats"] {
		t.Error("ResourceItem.resource_type.enum still carries stale 'nats' — should be 'queue'")
	}

	// ClaimPreviewResponse.resources[] must $ref ResourceItem (hoist) so the
	// two enums can't drift again.
	cp, ok := digMap(v, "components", "schemas", "ClaimPreviewResponse", "properties")
	if !ok {
		t.Fatal("ClaimPreviewResponse.properties missing")
	}
	resources, _ := cp["resources"].(map[string]any)
	items, _ := resources["items"].(map[string]any)
	ref, _ := items["$ref"].(string)
	if !strings.HasSuffix(ref, "/ResourceItem") {
		t.Errorf("ClaimPreviewResponse.resources.items must $ref ResourceItem to prevent enum drift; got %q", ref)
	}
}

// TestOpenAPI_DeployStatusEnumIncludesDeploying guards Wave FIX-E #C10 — the
// DeployResponse.item.status (and the sibling DeployItem) enum was
// ["building","healthy","failed","stopped"] but the live worker writes
// "deploying" as an intermediate state. Agents that strictly validated
// against the enum would reject perfectly-good poll responses.
func TestOpenAPI_DeployStatusEnumIncludesDeploying(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	check := func(label string, enumAny []any) {
		got := map[string]bool{}
		for _, e := range enumAny {
			if s, _ := e.(string); s != "" {
				got[s] = true
			}
		}
		for _, w := range []string{"building", "deploying", "healthy", "failed", "stopped"} {
			if !got[w] {
				t.Errorf("%s.status.enum missing %q", label, w)
			}
		}
	}

	// DeployResponse.item.status
	props, ok := digMap(v, "components", "schemas", "DeployResponse", "properties")
	if !ok {
		t.Fatal("DeployResponse.properties missing")
	}
	item, _ := props["item"].(map[string]any)
	itemProps, _ := item["properties"].(map[string]any)
	st, _ := itemProps["status"].(map[string]any)
	enumAny, _ := st["enum"].([]any)
	check("DeployResponse.item", enumAny)

	// DeployItem.status (parallel shape — list endpoint)
	di, ok := digMap(v, "components", "schemas", "DeployItem", "properties")
	if !ok {
		t.Fatal("DeployItem.properties missing")
	}
	st2, _ := di["status"].(map[string]any)
	enumAny2, _ := st2["enum"].([]any)
	check("DeployItem", enumAny2)
}

// TestOpenAPI_TeamSummaryTierEnumCoversAllTiers guards Wave FIX-E #C11 — the
// TeamSummaryResponse.tier enum was ["anonymous","free","hobby","pro","team"]
// but the live teams.plan_tier column carries hobby_plus, growth, AND yearly
// variants. A dashboard that validated against this enum would reject
// summaries for any Plus / yearly customer.
func TestOpenAPI_TeamSummaryTierEnumCoversAllTiers(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "TeamSummaryResponse", "properties")
	if !ok {
		t.Fatal("TeamSummaryResponse.properties missing")
	}
	tier, _ := props["tier"].(map[string]any)
	enumAny, _ := tier["enum"].([]any)
	got := map[string]bool{}
	for _, e := range enumAny {
		if s, _ := e.(string); s != "" {
			got[s] = true
		}
	}
	for _, w := range []string{"hobby_plus", "growth", "hobby_yearly", "pro_yearly"} {
		if !got[w] {
			t.Errorf("TeamSummaryResponse.tier.enum missing %q — Plus / yearly customers will fail strict validation", w)
		}
	}
}

// TestOpenAPI_ErrorResponseDocumentsClaimURL guards Wave FIX-E #C12 — the
// provisioning 402 envelope on free_tier_recycle_requires_claim carries a
// claim_url field on the wire, but the schema didn't declare it. Agents
// that strict-parse against the schema would either drop the field or fail
// to surface the claim flow back to the user.
func TestOpenAPI_ErrorResponseDocumentsClaimURL(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "ErrorResponse", "properties")
	if !ok {
		t.Fatal("ErrorResponse.properties missing")
	}
	if _, ok := props["claim_url"]; !ok {
		t.Error("ErrorResponse.properties.claim_url missing — free_tier_recycle_requires_claim envelope returns it on the wire but the schema is silent")
	}
}

// TestOpenAPI_StartIs302NotHTML guards Wave FIX-E #C13 — GET /start used to be
// documented as a 200 HTML response, but the actual handler issues a 302
// Location redirect to the dashboard claim page. Agents following the spec
// to "render HTML" would fail; agents following an HTTP client default of
// "follow redirects" would work but be confused why their content-type
// expectations don't match.
func TestOpenAPI_StartIs302NotHTML(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	get, ok := digMap(v, "paths", "/start", "get")
	if !ok {
		t.Fatal("/start GET missing from spec")
	}
	responses, _ := get["responses"].(map[string]any)
	if _, ok := responses["302"]; !ok {
		t.Error("/start GET must document 302 — the handler issues a redirect, not an HTML page")
	}
	if r302, ok := responses["302"].(map[string]any); ok {
		headers, _ := r302["headers"].(map[string]any)
		if _, ok := headers["Location"]; !ok {
			t.Error("/start 302 must document the Location header — agents need to know to follow it")
		}
	}
}

// TestOpenAPI_ProvisionResponsesDocumentUpgradeJWT guards Wave FIX-E #C17 —
// every anonymous provision response writes upgrade_jwt to the wire (so
// agents can POST /claim without string-parsing the URL), but the OpenAPI
// schemas for those responses didn't declare the field. An agent reading
// the spec alone would not know upgrade_jwt is on the wire and would fall
// back to URL-stripping (which the policy memory says we explicitly do
// not want).
func TestOpenAPI_ProvisionResponsesDocumentUpgradeJWT(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	for _, schemaName := range []string{
		"DBProvisionResponse",
		"CacheProvisionResponse",
		"NoSQLProvisionResponse",
		"QueueProvisionResponse",
		"StorageProvisionResponse",
		"WebhookProvisionResponse",
		"VectorProvisionResponse",
	} {
		props, ok := digMap(v, "components", "schemas", schemaName, "properties")
		if !ok {
			t.Errorf("%s missing", schemaName)
			continue
		}
		if _, ok := props["upgrade_jwt"]; !ok {
			t.Errorf("%s.properties.upgrade_jwt missing — agents must be able to discover the field from the spec alone", schemaName)
		}
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

// TestOpenAPI_CoversAllRegisteredRoutes is the regression gate for H4 — every
// (method, path) registered in router.go MUST also appear in openapi.go. The
// previous "did the writer remember to document it?" trust model burned us
// repeatedly in Retro-3 (capabilities, status, incidents, /api/v1/team
// GET/PATCH, llms.txt all shipped without spec entries). This test enumerates
// the live route registrations by string-parsing router.go and asserts each
// one is described in the OpenAPI Paths map.
//
// Intentionally hidden routes are whitelisted with explicit justification
// below — admin/* (unguessable prefix), email-provider receivers (ops-only),
// worker M2M, and dashboard-only telemetry surfaces.
//
// Why parse router.go as text instead of running the live Fiber app: building
// the app would require a real DB pool, Redis client, plans registry, GeoDB
// pointers, etc. — the test would be an integration test, not a unit test.
// The string parser is good enough because every route in router.go uses one
// of the documented registration patterns (app.Get("/path"), api.Post(...),
// deployGroup.Patch(...), etc.) — the test is calibrated against the live
// file and any new registration style would surface as a failure here.
func TestOpenAPI_CoversAllRegisteredRoutes(t *testing.T) {
	var spec map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &spec); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, _ := spec["paths"].(map[string]any)
	if paths == nil {
		t.Fatal("openAPISpec missing paths map")
	}

	// Locate router.go relative to this test file. Do NOT hardcode an
	// absolute path; CI runs from a checkout root that differs per platform.
	routerPath := filepath.Join("..", "router", "router.go")
	src, err := os.ReadFile(routerPath)
	if err != nil {
		t.Fatalf("read router.go: %v", err)
	}

	routes := extractRouterRoutes(string(src))
	if len(routes) == 0 {
		t.Fatal("extractRouterRoutes returned 0 — the parser is out of sync with router.go syntax")
	}

	// Whitelist of (method, openapi-path) tuples intentionally omitted from
	// the public spec. Categories:
	//
	//   1. admin/* routes — already filtered via r.isAdmin below. The
	//      adminGroup registrations sit under the unguessable
	//      ADMIN_PATH_PREFIX in production; documenting them defeats the
	//      prefix gate. See router.go's "Gate 1" comment.
	//   2. Email-provider feedback receivers (Brevo, SES) — public, HMAC/SNS-
	//      verified, configured by ops, not consumed by callers reading
	//      the spec.
	//   3. Worker-to-api machine-to-machine internal terminate — shared-
	//      secret auth, no agent should call it directly.
	//   4. Dashboard-only telemetry surfaces — usage/wall (read by the
	//      dashboard's polling nudge banner) and experiments/converted
	//      (A/B click sink). Agents shouldn't drive these and adding them
	//      to the agent-facing spec would muddy the contract.
	intentionallyHidden := map[string]bool{
		"POST /api/v1/email/webhook/brevo": true,
		"POST /api/v1/email/webhook/ses":   true,
		// API-98 (QA 2026-05-29): provider-dashboard pre-flight GET on the
		// webhook URL — returns 405 + Allow: POST so a dashboard sees
		// "URL exists, method wrong" rather than silently abandoning a
		// 401. Not an agent-facing surface; stays out of OpenAPI.
		"GET /api/v1/email/webhook/brevo":     true,
		"GET /api/v1/email/webhook/ses":       true,
		"POST /internal/teams/{id}/terminate": true,
		// Worker-only resend driver. Auth is the shared
		// WORKER_INTERNAL_JWT_SECRET HS256 token; agents must never call
		// this directly. Exposing it in the public OpenAPI would
		// mislead agents into thinking it's a customer-facing surface.
		"POST /internal/email/resend-magic-link": true,
		// Worker-only manual-backup quota refund (FIX-H #65/#Q47). Same
		// WORKER_INTERNAL_JWT_SECRET HS256 M2M auth as the two /internal
		// routes above — the worker's customer_backup_runner calls it
		// when a manual backup fails terminally. Not a customer-facing
		// surface, so it stays out of the agent-facing OpenAPI spec.
		"POST /internal/teams/{id}/backup-quota/refund": true,
		// CI-only ephemeral-test-account surface. Guarded by E2E_ACCOUNT_TOKEN
		// (route registers inert / 404s unless the token is configured) and
		// only ever driven by the E2E harness against prod — never a
		// customer-facing agent surface. Documenting it in the agent-facing
		// OpenAPI would mislead agents into thinking they can mint accounts.
		// Same rationale as the WORKER_INTERNAL_JWT_SECRET /internal routes above.
		"POST /internal/e2e/account":             true,
		"DELETE /internal/e2e/account/{team_id}": true,
		"GET /api/v1/usage/wall":                 true,
		"POST /api/v1/experiments/converted":     true,
		// POST /auth/exchange — browser-only bridge between the magic-link
		// / OAuth callback and the SPA. The handler reads the transient
		// instanode_session_exchange cookie (Path=/auth/exchange,
		// Max-Age=30s) and returns the embedded JWT in the body so the
		// SPA can swap into Bearer-only mode. Documenting it in the
		// agent-facing OpenAPI would mislead CLI/MCP/SDK agents into
		// thinking cookies are a valid auth mechanism — they're not
		// (CLAUDE.md "Live API surface" + auth_beareronly_authp0_test.go).
		"POST /auth/exchange": true,
		// BUG-API-411 (QA 2026-05-29): RFC 9116 security.txt is a
		// security-researcher disclosure surface, not an agent-facing
		// API. The body is hand-crafted text/plain matching RFC §2.3,
		// not JSON, so it has no OpenAPI schema. Both the canonical
		// .well-known path and the apex fallback are excluded from the
		// public spec on the same rationale. See security_txt.go for
		// the builder and security_txt_test.go for the wire contract.
		"GET /.well-known/security.txt": true,
		"GET /security.txt":             true,
		// GitHub App install flow (P4.1) is flag-gated OFF (GITHUB_APP_ENABLED).
		// While off, both endpoints return 501 github_app_disabled — documenting
		// them in the agent-facing OpenAPI now would mislead agents into thinking
		// the App path works. The contract sync (OpenAPI + llms.txt + MCP) lands
		// in P4.3 alongside the flag flip. See SCOPE-P4-github-app + github_app.go.
		"GET /integrations/github/install":  true,
		"GET /integrations/github/callback": true,
		// App-level GitHub webhook (P4.2) — GitHub-facing (HMAC-authed), not an
		// agent-facing API; flag-gated OFF until P4.3. Documenting it in the
		// agent OpenAPI would mislead agents (same rationale as the manual
		// /webhooks/github/{webhook_id} receiver, which is also not in the spec).
		"POST /webhooks/github": true,
	}

	var missing []string
	for _, r := range routes {
		if r.isAdmin {
			continue
		}
		openapiPath := fiberParamsToOpenAPI(r.path)

		key := r.method + " " + openapiPath
		if intentionallyHidden[key] {
			continue
		}

		entry, ok := paths[openapiPath].(map[string]any)
		if !ok {
			missing = append(missing, key+"  (no path entry)")
			continue
		}
		methodKey := strings.ToLower(r.method)
		if _, ok := entry[methodKey].(map[string]any); !ok {
			missing = append(missing, key+"  (path entry exists, method missing)")
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("OpenAPI spec is missing %d route(s) that router.go registers. Add them to internal/handlers/openapi.go (and a schema if appropriate) or extend the intentionallyHidden whitelist in this test with a comment justifying the omission:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// routerRoute is one (method, path, isAdmin) triple extracted from router.go.
type routerRoute struct {
	method  string // "GET", "POST", "PUT", "PATCH", "DELETE"
	path    string // e.g. "/db/new", "/api/v1/team" — already prefixed
	isAdmin bool   // true if registered on adminGroup
}

// extractRouterRoutes walks router.go's source text and emits one routerRoute
// per registration. Supports the five Fiber registration patterns the live
// router uses:
//
//   - app.<Method>("/path", ...)         registered at root
//   - api.<Method>("/path", ...)         prefixed with /api/v1
//   - adminGroup.<Method>("/path", ...)  admin (filtered out by caller)
//   - deployGroup.<Method>("/path", ...) prefixed with /deploy
//   - internal.<Method>("/path", ...)    prefixed with /internal (dev-only)
//
// The parser is intentionally conservative — it expects a literal "(" right
// after the method name and a quoted path as the first argument. Anything
// else (interpolated paths, dynamic registration) is skipped, which is fine
// because router.go uses only literal paths today.
func extractRouterRoutes(src string) []routerRoute {
	patterns := []struct {
		groupRe   *regexp.Regexp
		urlPrefix string
		isAdmin   bool
	}{
		{regexp.MustCompile(`\bapp\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "", false},
		{regexp.MustCompile(`\bapi\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/api/v1", false},
		{regexp.MustCompile(`\badminGroup\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/api/v1/<admin>", true},
		{regexp.MustCompile(`\bdeployGroup\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/deploy", false},
		{regexp.MustCompile(`\binternal\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/internal", false},
	}

	var out []routerRoute
	for _, p := range patterns {
		for _, m := range p.groupRe.FindAllStringSubmatch(src, -1) {
			method := strings.ToUpper(m[1])
			path := m[2]
			if p.urlPrefix != "" {
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				path = p.urlPrefix + path
			}
			out = append(out, routerRoute{method: method, path: path, isAdmin: p.isAdmin})
		}
	}
	return out
}

// fiberParamsToOpenAPI converts ":param" segments to "{param}" so the
// extracted router path can be looked up directly in the OpenAPI paths map.
// e.g. "/api/v1/resources/:id/family" → "/api/v1/resources/{id}/family".
func fiberParamsToOpenAPI(path string) string {
	if !strings.Contains(path, ":") {
		return path
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if strings.HasPrefix(seg, ":") {
			segments[i] = "{" + seg[1:] + "}"
		}
	}
	return strings.Join(segments, "/")
}

// TestOpenAPI_DeployItemSchemaMatchesHandler is the P1-H regression guard
// (bug hunt 2026-05-17 round 2). The DeployItem schema had drifted ~15 fields
// behind deploymentToMap. Every field the handler can emit must be documented.
func TestOpenAPI_DeployItemSchemaMatchesHandler(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "DeployItem", "properties")
	if !ok {
		t.Fatal("could not navigate to DeployItem.properties")
	}
	// Every key handlers.deploymentToMap can put in the fiber.Map.
	want := []string{
		"id", "token", "app_id", "provider_id", "name", "url", "status", "tier",
		"environment", "env", "port", "private", "allowed_ips", "team_id",
		"created_at", "updated_at", "error", "resource_id", "notify_webhook",
		"notify_state", "notify_attempts", "notify_secret_set", "ttl_policy",
		"expires_at", "reminders_sent", "make_permanent_url", "extend_ttl_url",
		"failure",
	}
	for _, f := range want {
		if _, ok := props[f]; !ok {
			t.Errorf("DeployItem schema missing field %q that deploymentToMap emits", f)
		}
	}
}

// TestOpenAPI_AuthMeResponseSchemaMatchesHandler — P1-H guard for AuthMeResponse.
func TestOpenAPI_AuthMeResponseSchemaMatchesHandler(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "AuthMeResponse", "properties")
	if !ok {
		t.Fatal("could not navigate to AuthMeResponse.properties")
	}
	want := []string{
		"ok", "user_id", "team_id", "email", "tier", "plan_display_name",
		"experiments", "is_platform_admin", "admin_path_prefix", "read_only",
		"impersonated_by",
	}
	for _, f := range want {
		if _, ok := props[f]; !ok {
			t.Errorf("AuthMeResponse schema missing field %q that GetCurrentUser emits", f)
		}
	}
}

// TestOpenAPI_ResourceItemSchemaMatchesHandler — P1-H guard for ResourceItem.
func TestOpenAPI_ResourceItemSchemaMatchesHandler(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	props, ok := digMap(v, "components", "schemas", "ResourceItem", "properties")
	if !ok {
		t.Fatal("could not navigate to ResourceItem.properties")
	}
	want := []string{
		"id", "token", "resource_type", "name", "env", "tier", "status",
		"cloud_vendor", "country_code", "storage_bytes", "storage_limit_bytes",
		"connections_limit", "storage_exceeded", "expires_at", "paused_at",
		"team_id", "created_at",
	}
	for _, f := range want {
		if _, ok := props[f]; !ok {
			t.Errorf("ResourceItem schema missing field %q that resourceToMap emits", f)
		}
	}
}
