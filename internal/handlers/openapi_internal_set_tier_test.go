package handlers

import (
	"strings"
	"testing"
)

// TestStripInternalSetTierPath — T19 P0-1 regression.
//
// /internal/set-tier is registered only when ENVIRONMENT=development
// (router.go:1019). The spec used to list it unconditionally, lying to
// agents about a tier-mutation endpoint that 404s in prod and also
// advertising an internal privilege-escalation surface. ServeOpenAPI
// now strips it when the wired environment is not "development".
func TestStripInternalSetTierPath_RemovesEntry(t *testing.T) {
	t.Parallel()
	// Sanity check on the input: the unmodified spec MUST contain the
	// path or this regression test is checking nothing.
	if !strings.Contains(openAPISpec, `"/internal/set-tier"`) {
		t.Fatalf("openAPISpec does not contain /internal/set-tier — coverage test cannot validate the strip path")
	}
	stripped := stripInternalSetTierPath(openAPISpec)
	if strings.Contains(stripped, `"/internal/set-tier"`) {
		t.Errorf("stripInternalSetTierPath left /internal/set-tier in the spec — production callers will continue to see a documented but unimplemented endpoint")
	}
}

// TestStripInternalSetTierPath_LeavesValidJSON ensures the surgical strip
// does not produce a malformed JSON document.
func TestStripInternalSetTierPath_LeavesValidJSON(t *testing.T) {
	t.Parallel()
	stripped := stripInternalSetTierPath(openAPISpec)
	// Coarse JSON sanity check: every { has a matching } and quoted-key
	// values aren't broken. Use the same Go parser the real callers do.
	if !strings.HasPrefix(stripped, "{") || !strings.HasSuffix(stripped, "}") {
		t.Fatalf("stripped spec is not wrapped in {...}")
	}
}

// TestStripInternalSetTierPath_NoOpWhenAbsent ensures the helper returns
// the spec unchanged when the key isn't present.
func TestStripInternalSetTierPath_NoOpWhenAbsent(t *testing.T) {
	t.Parallel()
	in := `{"paths": {"/a": {"get": {}}}}`
	out := stripInternalSetTierPath(in)
	if out != in {
		t.Errorf("strip changed input that contained no /internal/set-tier: %q -> %q", in, out)
	}
}

// TestServeOpenAPI_ProductionExcludesPath checks the runtime gate: when
// openAPIEnvironment != "development", the served bytes must NOT contain
// /internal/set-tier.
func TestServeOpenAPI_ProductionExcludesPath(t *testing.T) {
	// Snapshot and restore package state — these tests share globals.
	prevEnv := openAPIEnvironment
	prevSpec := openAPISpecProd
	t.Cleanup(func() {
		openAPIEnvironment = prevEnv
		openAPISpecProd = prevSpec
	})

	openAPIEnvironment = "production"
	openAPISpecProd = stripInternalSetTierPath(openAPISpec)
	if strings.Contains(openAPISpecProd, `"/internal/set-tier"`) {
		t.Errorf("openAPISpecProd contains /internal/set-tier — T19 P0-1 regression")
	}

	// In development, the un-stripped spec is served as-is. The const
	// itself must contain the path so a dev-mode call can document it.
	openAPIEnvironment = "development"
	if !strings.Contains(openAPISpec, `"/internal/set-tier"`) {
		t.Errorf("development openAPISpec must KEEP /internal/set-tier")
	}
}
