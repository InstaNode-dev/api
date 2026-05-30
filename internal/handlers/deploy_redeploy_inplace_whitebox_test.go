package handlers

// deploy_redeploy_inplace_whitebox_test.go — unit-coverage for the
// shouldRedeployInPlace helper used by POST /deploy/new redeploy=true.
//
// The HTTP-level tests in deploy_redeploy_inplace_test.go drive the helper
// indirectly via multipart bodies, but two arms only fire when the helper
// is called directly:
//
//   - nil-form arm (defensive guard for callers that pre-parse the form
//     and pass nil — currently no in-tree caller, but the helper is
//     exported-by-convention to the package and must stay panic-free).
//   - explicit-false arm (the lower switch's `default:` branch, taken
//     when the field is present-but-not-truthy — "false", "no", "0",
//     "off", etc.). The HTTP suite's negative test happens to omit the
//     field entirely, which routes through the upper `!ok` arm and skips
//     this one.
//
// Both are pure-functional unit tests — no DB, no Fiber, no goroutines.

import (
	"mime/multipart"
	"testing"
)

// TestShouldRedeployInPlace_NilForm pins the defensive nil-form guard
// (deploy.go:205-207). Without this arm a malformed request that bypassed
// MultipartForm parsing would NPE inside the helper.
func TestShouldRedeployInPlace_NilForm(t *testing.T) {
	if shouldRedeployInPlace(nil) {
		t.Fatal("shouldRedeployInPlace(nil) must return false — defensive guard")
	}
}

// TestShouldRedeployInPlace_FalsyValues pins the lower switch's `default:`
// arm (deploy.go:215-216). Every value listed here is present-but-not-truthy
// and MUST route through the fresh-deploy path, NOT the in-place path. If
// any of these silently flipped to true, an agent that POSTed
// redeploy=false (e.g. "always set the flag explicitly") would clobber its
// previous deploy by accident.
func TestShouldRedeployInPlace_FalsyValues(t *testing.T) {
	cases := []string{"false", "False", "FALSE", "no", "NO", "0", "off", "", " ", "anything-else"}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			form := &multipart.Form{Value: map[string][]string{"redeploy": {val}}}
			if shouldRedeployInPlace(form) {
				t.Fatalf("shouldRedeployInPlace(%q) = true, want false (falsy values must never trigger in-place path)", val)
			}
		})
	}
}

// TestShouldRedeployInPlace_TruthyValues sanity-pins the truthy arms so a
// future refactor that narrowed the accepted set (e.g. dropped "yes")
// fails loudly here rather than silently breaking the agent contract
// surfaced in the OpenAPI spec.
func TestShouldRedeployInPlace_TruthyValues(t *testing.T) {
	cases := []string{"true", "TRUE", "True", "1", "yes", "YES", " true ", "\ttrue\n"}
	for _, val := range cases {
		val := val
		t.Run(val, func(t *testing.T) {
			form := &multipart.Form{Value: map[string][]string{"redeploy": {val}}}
			if !shouldRedeployInPlace(form) {
				t.Fatalf("shouldRedeployInPlace(%q) = false, want true (documented truthy value)", val)
			}
		})
	}
}

// TestShouldRedeployInPlace_MissingField covers the upper `!ok` arm — the
// dominant runtime case (most /deploy/new callers don't send the field at
// all). The lower switch must not be reached in this branch.
func TestShouldRedeployInPlace_MissingField(t *testing.T) {
	form := &multipart.Form{Value: map[string][]string{"name": {"foo"}}}
	if shouldRedeployInPlace(form) {
		t.Fatal("shouldRedeployInPlace with no `redeploy` field must return false")
	}
}

// TestShouldRedeployInPlace_EmptyValuesSlice covers the `len(vals) == 0`
// arm — a quirk multipart can produce when the field key is present with
// an empty values slice. Same false posture as the missing-field arm.
func TestShouldRedeployInPlace_EmptyValuesSlice(t *testing.T) {
	form := &multipart.Form{Value: map[string][]string{"redeploy": {}}}
	if shouldRedeployInPlace(form) {
		t.Fatal("shouldRedeployInPlace with empty values slice must return false")
	}
}
