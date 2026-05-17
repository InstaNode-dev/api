package handlers

// deploy_internal_env_test.go — P1-N coverage (bug hunt 2026-05-17 round 2).
//
// The deployment display name is stashed in env_vars under the internal key
// "_name" (deployNameEnvKey) because there is no dedicated DB column. That key
// must NOT (a) be injected into the customer container's env, nor (b) be
// echoed in the `env` field of GET /deploy/:id.
//
// stripInternalEnvKeys covers the compute-injection path; redactEnvVars now
// drops internalEnvKeys on the outbound path.

import (
	"reflect"
	"testing"
)

// TestStripInternalEnvKeys_RemovesName verifies the compute-injection helper
// drops "_name" while preserving every real application env var.
func TestStripInternalEnvKeys_RemovesName(t *testing.T) {
	in := map[string]string{
		deployNameEnvKey: "my-cool-app",
		"PORT":           "8080",
		"NODE_ENV":       "production",
	}
	got := stripInternalEnvKeys(in)

	if _, leaked := got[deployNameEnvKey]; leaked {
		t.Errorf("%q must be stripped from the customer container env", deployNameEnvKey)
	}
	want := map[string]string{"PORT": "8080", "NODE_ENV": "production"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stripInternalEnvKeys = %#v, want %#v", got, want)
	}
	// Original map must not be mutated.
	if _, ok := in[deployNameEnvKey]; !ok {
		t.Error("stripInternalEnvKeys mutated the input map")
	}
}

// TestRedactEnvVars_DropsInternalName is the P1-N outbound-leak guard:
// GET /deploy/:id must not surface "_name" in the env field.
func TestRedactEnvVars_DropsInternalName(t *testing.T) {
	in := map[string]string{
		deployNameEnvKey: "my-cool-app",
		"PORT":           "8080",
		"DATABASE_URL":   "postgres://u:p@host/db",
	}
	got := redactEnvVars(in)

	if _, leaked := got[deployNameEnvKey]; leaked {
		t.Errorf("redactEnvVars leaked internal key %q in outbound JSON", deployNameEnvKey)
	}
	if got["PORT"] != "8080" {
		t.Errorf("redactEnvVars dropped a real env var: PORT=%q", got["PORT"])
	}
	// The credential URL is still masked — internal-key stripping must not
	// regress the existing secret redaction.
	if got["DATABASE_URL"] != envRedactedMask {
		t.Errorf("DATABASE_URL not masked: got %q", got["DATABASE_URL"])
	}
}

// TestStripInternalEnvKeys_Empty verifies the nil/empty fast path.
func TestStripInternalEnvKeys_Empty(t *testing.T) {
	if got := stripInternalEnvKeys(nil); got != nil {
		t.Errorf("stripInternalEnvKeys(nil) = %#v, want nil", got)
	}
}
