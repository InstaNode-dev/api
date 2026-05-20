package handlers

// B13 contract guard — registry-iterating per CLAUDE.md rule 18.

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

const provisioningNewPathSuffix = "/new"

var provisioningRoots = []string{
	"/db", "/cache", "/nosql", "/queue", "/storage", "/webhook", "/vector",
}

func TestB13_ProvisioningPathsDocumentDedupReplayAnd429(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal([]byte(openAPISpec), &v); err != nil {
		t.Fatalf("openAPISpec parse: %v", err)
	}
	paths := v["paths"].(map[string]any)
	rootSet := map[string]bool{}
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
		t.Fatal("no /*/new paths discovered")
	}
	wantCodes := []string{"200", "201", "429"}
	for _, p := range newPaths {
		entry := paths[p].(map[string]any)
		post := entry["post"].(map[string]any)
		responses := post["responses"].(map[string]any)
		for _, code := range wantCodes {
			if _, ok := responses[code]; !ok {
				t.Errorf("%s.post.responses[%s]: missing (B13-F2/F4/F5)", p, code)
			}
		}
	}
}

func TestB13_ProvisioningErrorEnvelopesPointAtErrorResponse(t *testing.T) {
	var v map[string]any
	json.Unmarshal([]byte(openAPISpec), &v)
	paths := v["paths"].(map[string]any)
	rootSet := map[string]bool{}
	for _, r := range provisioningRoots {
		rootSet[r] = true
	}
	for p, raw := range paths {
		if !strings.HasSuffix(p, provisioningNewPathSuffix) {
			continue
		}
		root := strings.TrimSuffix(p, provisioningNewPathSuffix)
		if !rootSet[root] {
			continue
		}
		entry := raw.(map[string]any)
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
			rsp := rspRaw.(map[string]any)
			content, ok := rsp["content"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing content (B13-F19)", p, code)
				continue
			}
			appJSON, ok := content["application/json"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing application/json", p, code)
				continue
			}
			schema, ok := appJSON["schema"].(map[string]any)
			if !ok {
				t.Errorf("%s.post.responses[%s]: missing schema", p, code)
				continue
			}
			ref, _ := schema["$ref"].(string)
			if ref != "#/components/schemas/ErrorResponse" {
				t.Errorf("%s.post.responses[%s].schema.$ref = %q; want #/components/schemas/ErrorResponse (B13-F7/F8/F19)", p, code, ref)
			}
		}
	}
}

func TestB13_ErrorResponseRequiredFieldsRetained(t *testing.T) {
	var v map[string]any
	json.Unmarshal([]byte(openAPISpec), &v)
	schema, _ := digMap(v, "components", "schemas", "ErrorResponse")
	requiredRaw := schema["required"].([]any)
	got := map[string]bool{}
	for _, r := range requiredRaw {
		got[r.(string)] = true
	}
	for _, field := range []string{"ok", "error", "message", "retry_after_seconds"} {
		if !got[field] {
			t.Errorf("ErrorResponse.required missing %q", field)
		}
	}
}

func TestB13_HealthResponseFieldsAreRequired(t *testing.T) {
	var v map[string]any
	json.Unmarshal([]byte(openAPISpec), &v)
	schema, _ := digMap(v, "components", "schemas", "HealthResponse")
	requiredRaw, ok := schema["required"].([]any)
	if !ok {
		t.Fatal("HealthResponse.required must be a list (B13-F17)")
	}
	got := map[string]bool{}
	for _, r := range requiredRaw {
		got[r.(string)] = true
	}
	for _, field := range []string{"ok", "service", "commit_id"} {
		if !got[field] {
			t.Errorf("HealthResponse.required missing %q", field)
		}
	}
}

func TestB13_DedupReplayHelperSetsCorrectHeaders(t *testing.T) {
	if idempotentReplayHeaderKey != "X-Idempotent-Replay" {
		t.Errorf("idempotentReplayHeaderKey = %q (B13-F4)", idempotentReplayHeaderKey)
	}
	if idempotencySourceHeaderKey != "X-Idempotency-Source" {
		t.Errorf("idempotencySourceHeaderKey = %q (B13-F4)", idempotencySourceHeaderKey)
	}
	if idempotencySourceHandlerDedup != "handler-dedup" {
		t.Errorf("idempotencySourceHandlerDedup = %q (B13-F4)", idempotencySourceHandlerDedup)
	}
}
