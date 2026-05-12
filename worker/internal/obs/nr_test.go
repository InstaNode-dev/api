// Tests for the New Relic init helper. The hard requirement is the
// fail-open contract: missing NEW_RELIC_LICENSE_KEY must return (nil, nil)
// with a warning log, NEVER an error and NEVER a crash.
//
// We don't test the success path here — it would require either embedding a
// fake NR collector or carrying a real license key in CI secrets, neither of
// which is worth the complexity for a thin bootstrap helper.
package obs

import (
	"testing"
)

// TestInitNewRelic_FailOpenOnMissingLicenseKey is the primary contract test.
// With no env var, the helper must return (nil, nil). We use t.Setenv to
// guarantee an empty value even on developer machines where the env might be
// set in their shell.
func TestInitNewRelic_FailOpenOnMissingLicenseKey(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")

	app, err := InitNewRelic()
	if err != nil {
		t.Fatalf("expected nil error on missing license key, got %v", err)
	}
	if app != nil {
		t.Fatalf("expected nil application on missing license key, got %v", app)
	}
}

// TestWaitForConnection_NilSafe is a trivial guard for the helper that some
// boot-time code paths may call before the app is fully constructed.
func TestWaitForConnection_NilSafe(t *testing.T) {
	// Must not panic.
	WaitForConnection(nil)
}
