package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitNewRelic_FailOpenOnEmptyLicense verifies the contract that
// missing NEW_RELIC_LICENSE_KEY does NOT prevent the api binary from
// booting. Returning nil lets the Fiber middleware and metric helpers
// degrade to no-ops; an error here would crash every CI run and every
// local `make run` (since neither sets the license key).
func TestInitNewRelic_FailOpenOnEmptyLicense(t *testing.T) {
	prev := os.Getenv("NEW_RELIC_LICENSE_KEY")
	t.Cleanup(func() { _ = os.Setenv("NEW_RELIC_LICENSE_KEY", prev) })
	require.NoError(t, os.Unsetenv("NEW_RELIC_LICENSE_KEY"))

	app := initNewRelic("api")
	require.Nil(t, app, "initNewRelic must return nil when NEW_RELIC_LICENSE_KEY is empty (fail-open contract)")
}

// TestResolveImageDigest_UnsetFallsBackToLocalBuild pins the contract
// the spec calls out as test case 8: when k8s hasn't populated
// IMAGE_DIGEST (`make run`, `go test`, smoke binaries) the recorded
// digest is the fixed sentinel "local-build" rather than an empty
// string. Empty strings would still satisfy the table's NOT NULL but
// would collide with the unique index in confusing ways once two
// different un-ldflagged commits boot — the sentinel makes the local-
// dev case visibly distinct in the admin endpoint's output.
func TestResolveImageDigest_UnsetFallsBackToLocalBuild(t *testing.T) {
	prev, hadPrev := os.LookupEnv(imageDigestEnvVar)
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(imageDigestEnvVar, prev)
		} else {
			_ = os.Unsetenv(imageDigestEnvVar)
		}
	})
	require.NoError(t, os.Unsetenv(imageDigestEnvVar))

	assert.Equal(t, imageDigestFallback, resolveImageDigest(),
		`unset IMAGE_DIGEST must resolve to "local-build" — the fixed sentinel`)
}

// TestResolveImageDigest_EmptyStringFallsBack — the env var being set
// but empty is the same as being unset. Catches the k8s-misconfig case
// where the fieldRef returns "" because the pod hasn't entered Running
// yet but the env injection happens before health-check gating.
func TestResolveImageDigest_EmptyStringFallsBack(t *testing.T) {
	t.Setenv(imageDigestEnvVar, "")
	assert.Equal(t, imageDigestFallback, resolveImageDigest(),
		"empty IMAGE_DIGEST must resolve to the fallback (whitespace-trimmed)")
}

// TestResolveImageDigest_RealValuePassesThrough — the happy path: when
// k8s gives us a real digest, we don't second-guess it. Whitespace is
// trimmed because the fieldRef path can leak a trailing newline through
// some operator pipelines.
func TestResolveImageDigest_RealValuePassesThrough(t *testing.T) {
	t.Setenv(imageDigestEnvVar, "  sha256:deadbeef  ")
	assert.Equal(t, "sha256:deadbeef", resolveImageDigest(),
		"real digest values are passed through, with surrounding whitespace trimmed")
}
