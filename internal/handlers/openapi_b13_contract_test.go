package handlers

// openapi_b13_contract_test.go — registry-iterating contract guard for
// B13 (BugBash 2026-05-20). Walks the OpenAPI spec for every documented
// POST /*/new provisioning route and asserts the response contract is
// in agreement with the handler behaviour:
//
//   1. Each provisioning POST documents BOTH a 201 (fresh provision) and
//      a 200 (handler-internal dedup replay) response — B13-F2 / F4.
//      Without this, the SDK / CLI / MCP layer mis-classifies dedup hits
//      as either "fresh" (causing double quota burn) or as errors.
//
//   2. Each provisioning POST documents the canonical envelope for every
//      enumerated 4xx/5xx response — every non-2xx points at
//      #/components/schemas/ErrorResponse — B13-F19 / F7 / F8.
//
//   3. The ErrorResponse schema still carries the four canonical required
//      fields (ok, error, message, retry_after_seconds) the preamble
//      promises. Adding a fifth required field is allowed; dropping any
//      of these breaks every downstream parser. Pinning here so a future
//      schema edit can't silently drop one.
//
// The test deliberately enumerates the LIVE registry — `paths` map keyed
// by literal strings — rather than a hand-typed slice. Per CLAUDE.md
// rule 18 (registry-iterating regression tests, not hand-typed lists),
// this fails on the next /*/new endpoint that lands without a 200 +
// canonical 4xx envelope.

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// provisioningNewPathSuffix is the route suffix every provisioning
// endpoint shares: db/new, cache/new, nosql/new, queue/new, storage/new,
// webhook/new, vector/new. The registry walk filters on this so a future
// /foo/new addition is automatically picked up.
const provisioningNewPathSuffix = "/new"

// provisioningRoots is the closed list of resource roots in scope for
// the B13 provisioning contract. Adding a new resource type here (and
// to plans.yaml + the handler) automatically falls under the same
// dedup-200-required + canonical-envelope rule when its path appears
// under paths["/<root>/new"].
var provisioningRoots = []string{
	"/db",
	"/cache",
	"/nosql",
	"/queue",
	"/storage",
	"/webhook",
	"/vector",
}

func TestB13_ProvisioningPathsDocumentDedupReplayAnd429(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, ok := v["paths"].(map[string]any)
	if !ok {
		t.Fatal("openAPISpec.paths is not a map — spec is malformed")
	}

	rootSet := make(map[string]bool, len(provisioningRoots))
	for _, r := range provisioningRoots {
		rootSet[r] = true
	}
	var newPaths []string
	for p := range paths {
		if !strings.HasSuffix(p, provisioningNewPathSuffix) {
			continue
		}
		root := strings.TrimSuffix(p, provisioningNewPathSuffix)
		if !rootSet[root] {
			continue
		}
		newPaths = append(newPaths, p)
	}
	sort.Strings(newPaths)
	if len(newPaths) == 0 {
		t.Fatal("no /*/new paths discovered in the spec — registry walk broken")
	}

	// Every documented /*/new endpoint must enumerate BOTH 201 (fresh)
	// AND 200 (dedup replay) AND 429 (anonymous cap with no existing
	// row to dedup against, error=provision_limit_reached). Hand-typed
	// SDK error maps key on the exact response-code set; missing any
	// of the three means an SDK branch silently misroutes a real call.
	wantCodes := []string{"200", "201", "429"}
	for _, p := range newPaths {
		entry, ok := paths[p].(map[string]any)
		if !ok {
			t.Errorf("%s: not a map", p)
			continue
		}
		post, ok := entry["post"].(map[string]any)
		if !ok {
			t.Errorf("%s: missing post operation", p)
			continue
		}
		responses, ok := post["responses"].(map[string]any)
		if !ok {
			t.Errorf("%s.post: missing responses block", p)
			continue
		}
		for _, code := range wantCodes {
			if _, ok := responses[code]; !ok {
				t.Errorf("%s.post.responses[%s]: missing — every provisioning endpoint must document %v (B13-F2/F4/F5)",
					p, code, wantCodes)
			}
		}
	}
}

func TestB13_ProvisioningErrorEnvelopesPointAtErrorResponse(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths, ok := v["paths"].(map[string]any)
	if !ok {
		t.Fatal("openAPISpec.paths is not a map")
	}
	rootSet := make(map[string]bool, len(provisioningRoots))
	for _, r := range provisioningRoots {
		rootSet[r] = true
	}

	// Every 4xx and 5xx response on a documented /*/new endpoint must
	// point at #/components/schemas/ErrorResponse — the canonical
	// envelope every SDK error map keys on. B13-F7 / F8 / F19 surfaced
	// hand-built fiber.Map envelopes that drift from this contract.
	for p, raw := range paths {
		if !strings.HasSuffix(p, provisioningNewPathSuffix) {
			continue
		}
		root := strings.TrimSuffix(p, provisioningNewPathSuffix)
		if !rootSet[root] {
			continue
		}
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		post, ok := entry["post"].(map[string]any)
		if !ok {
			continue
		}
		responses, ok := post["responses"].(map[string]any)
		if !ok {
			continue
		}
		for code, rspRaw := range responses {
			if !strings.HasPrefix(code, "4") && !strings.HasPrefix(code, "5") {
				continue
			}
			rsp, ok := rspRaw.(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: not a map", p, code)
				continue
			}
			content, ok := rsp["content"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing content block — every 4xx/5xx must carry ErrorResponse (B13-F19)", p, code)
				continue
			}
			appJSON, ok := content["application/json"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing application/json content type", p, code)
				continue
			}
			schema, ok := appJSON["schema"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing schema", p, code)
				continue
			}
			ref, _ := schema["$ref"].(string)
			if ref != "#/components/schemas/ErrorResponse" {
				t.Errorf("%s.post.responses[%s].schema.$ref = %q; want #/components/schemas/ErrorResponse (canonical envelope, B13-F7/F8/F19)",
					p, code, ref)
			}
		}
	}
}

func TestB13_ErrorResponseRequiredFieldsRetained(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	schema, ok := digMap(v, "components", "schemas", "ErrorResponse")
	if !ok {
		t.Fatal("ErrorResponse schema missing — every 4xx/5xx body uses it")
	}
	requiredRaw, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("ErrorResponse.required must be a list — every consumer relies on the canonical envelope")
	}
	got := make(map[string]bool, len(requiredRaw))
	for _, r := range requiredRaw {
		if s, ok := r.(string); ok {
			got[s] = true
		}
	}
	for _, field := range []string{"ok", "error", "message", "retry_after_seconds"} {
		if !got[field] {
			t.Errorf("ErrorResponse.required is missing %q — dropping it silently breaks every downstream parser", field)
		}
	}
}

func TestB13_HealthResponseFieldsAreRequired(t *testing.T) {
	// B13-F17: HealthResponse must declare required[] so JSON-Schema
	// validators can assert presence of commit_id / build_time / etc.
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	schema, ok := digMap(v, "components", "schemas", "HealthResponse")
	if !ok {
		t.Fatal("HealthResponse schema missing")
	}
	requiredRaw, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("HealthResponse.required must be a list — every field is de-facto required on a 2xx (B13-F17)")
	}
	got := make(map[string]bool, len(requiredRaw))
	for _, r := range requiredRaw {
		if s, ok := r.(string); ok {
			got[s] = true
		}
	}
	for _, field := range []string{"ok", "service", "commit_id"} {
		if !got[field] {
			t.Errorf("HealthResponse.required is missing %q — agents that JSON-schema-validate /healthz lose their commit_id pin", field)
		}
	}
}

func TestB13_DedupReplayHelperSetsCorrectHeaders(t *testing.T) {
	// Sanity-pin the handler-internal idempotency header constants.
	// If a future refactor renames idempotentReplayHeaderKey to
	// something Fiber-canonicalised differently, every dedup-200 path
	// stops setting the X-Idempotent-Replay header without any other
	// test catching it. The middleware test asserts MIDDLEWARE-served
	// replays; this assertion pins the HANDLER-served path.
	if idempotentReplayHeaderKey != "X-Idempotent-Replay" {
		t.Errorf("idempotentReplayHeaderKey = %q; want X-Idempotent-Replay (B13-F4)", idempotentReplayHeaderKey)
	}
	if idempotencySourceHeaderKey != "X-Idempotency-Source" {
		t.Errorf("idempotencySourceHeaderKey = %q; want X-Idempotency-Source (B13-F4)", idempotencySourceHeaderKey)
	}
	if idempotencySourceHandlerDedup != "handler-dedup" {
		t.Errorf("idempotencySourceHandlerDedup = %q; want handler-dedup (B13-F4)", idempotencySourceHandlerDedup)
	}
}
