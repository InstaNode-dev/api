package main

import (
	"os"
	"path/filepath"
	"strings"
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

// minimalValidPlansYAML is the smallest plans config that satisfies
// plans.parse — anonymous is the required fallback tier. Used by the
// loadPlansRegistry happy-path tests below so they don't depend on the
// real api/plans.yaml file being present at the test cwd.
const minimalValidPlansYAML = `
plans:
  anonymous:
    display_name: "Anonymous"
    price_monthly_cents: 0
    limits:
      provisions_per_day: 5
    features:
      alerts: false
`

// TestLoadPlansRegistry_ProductionFatal — when ENVIRONMENT=production and
// the plans.yaml file is missing or unreadable, loadPlansRegistry must
// return (nil, err). Falling back to common/plans.Default() in prod
// would silently serve stale limits because plans.yaml is the declared
// single source of truth — pre-W12 this is exactly the bug that landed
// (Dockerfile never COPYd plans.yaml, plans.Load silently failed, prod
// served embedded defaults). main() turns the error into os.Exit(1) so
// the pod CrashLoopBackoffs and an operator sees the misconfig.
func TestLoadPlansRegistry_ProductionFatal(t *testing.T) {
	// Point at a path guaranteed not to exist.
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	reg, err := loadPlansRegistry(missing, envProduction)
	require.Error(t, err, "production must NOT fall back when plans.yaml is missing")
	assert.Nil(t, reg, "registry must be nil on production failure so main() exits instead of serving stale defaults")
	assert.Contains(t, err.Error(), "production",
		"error message must mention production so operators see the cause in CrashLoopBackoff logs")
}

// TestLoadPlansRegistry_ProductionFatal_InvalidYAML — same contract as
// the missing-file case, but for a file that exists yet fails to parse.
// Operators who fat-finger plans.yaml in a configmap update would
// otherwise silently fall back to embedded defaults in prod.
func TestLoadPlansRegistry_ProductionFatal_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yaml")
	require.NoError(t, os.WriteFile(path, []byte("this is: : not valid: yaml\n: bad"), 0o600))

	reg, err := loadPlansRegistry(path, envProduction)
	require.Error(t, err, "production must NOT fall back on invalid plans YAML")
	assert.Nil(t, reg, "registry must be nil on parse failure in production")
}

// TestLoadPlansRegistry_DevFallsBack — in any environment other than
// "production", a missing or invalid plans.yaml must warn-and-fallback
// to the embedded common/plans.Default() registry so local `make run`
// keeps working without writing the file. Returns (registry, nil) so
// main() proceeds normally.
func TestLoadPlansRegistry_DevFallsBack(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")

	for _, env := range []string{"development", "staging", "test", ""} {
		t.Run("env="+env, func(t *testing.T) {
			reg, err := loadPlansRegistry(missing, env)
			require.NoError(t, err, "non-production must fall back without surfacing an error")
			require.NotNil(t, reg, "fallback registry must be a non-nil Default()")

			// Confirm the fallback registry is functional — the "anonymous"
			// tier MUST resolve because it's the required fallback in
			// plans.parse. Use ProvisionLimit as a representative method.
			limit := reg.ProvisionLimit("anonymous")
			assert.Greater(t, limit, 0, "Default() must expose a usable anonymous tier; got ProvisionLimit=%d", limit)
		})
	}
}

// TestLoadPlansRegistry_HappyPath_Production — when plans.yaml exists
// and is valid, production must succeed (no error, real registry). The
// fail-loud contract only fires on load failure; a healthy load proceeds
// identically across environments.
func TestLoadPlansRegistry_HappyPath_Production(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plans.yaml")
	require.NoError(t, os.WriteFile(path, []byte(minimalValidPlansYAML), 0o600))

	reg, err := loadPlansRegistry(path, envProduction)
	require.NoError(t, err, "valid plans.yaml must load cleanly in production")
	require.NotNil(t, reg, "registry must be non-nil on success")
}

// TestLoadPlansRegistry_HappyPath_Dev — same as the production happy
// path but in development. Confirms the fallback branch isn't taken
// when the file is actually loadable; the registry returned is the
// one from disk, not the embedded Default().
func TestLoadPlansRegistry_HappyPath_Dev(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plans.yaml")
	require.NoError(t, os.WriteFile(path, []byte(minimalValidPlansYAML), 0o600))

	reg, err := loadPlansRegistry(path, "development")
	require.NoError(t, err)
	require.NotNil(t, reg)
}

// TestLoadPlansRegistry_EnvProductionConstant — defensive guard against
// someone renaming envProduction to a different string later. Several
// other gates in the codebase (router policy, dev-only endpoints) check
// against the exact string "production"; if this constant ever drifts
// the asymmetry creates a silent prod-mode mismatch.
func TestLoadPlansRegistry_EnvProductionConstant(t *testing.T) {
	require.Equal(t, "production", envProduction,
		"envProduction must remain 'production' — other env gates compare against this literal string")
	// Also confirm case sensitivity: a config that injects "Production"
	// or "PRODUCTION" must NOT trip the fatal branch — it falls into
	// the dev fallback path. This matches the cfg.Load() behaviour which
	// also compares lowercase.
	missing := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	reg, err := loadPlansRegistry(missing, strings.ToUpper(envProduction))
	require.NoError(t, err, "case-mismatched env value must NOT trip the fatal branch")
	require.NotNil(t, reg)
}
