package plans_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/plans"
)

func TestDefault_LoadsWithoutError(t *testing.T) {
	r := plans.Default()
	require.NotNil(t, r)
}

func TestDefault_AllStandardTiersPresent(t *testing.T) {
	r := plans.Default()
	for _, tier := range []string{"anonymous", "free", "hobby", "pro", "team", "growth"} {
		p := r.Get(tier)
		assert.Equal(t, tier, p.Name, "tier %q must be in default registry", tier)
	}
}

func TestGet_UnknownTier_FallsBackToAnonymous(t *testing.T) {
	r := plans.Default()
	p := r.Get("enterprise-ultra")
	assert.Equal(t, "anonymous", p.Name, "unknown tier must fall back to anonymous plan")
}

func TestProvisionLimit_AnonymousIs5(t *testing.T) {
	r := plans.Default()
	assert.Equal(t, 5, r.ProvisionLimit("anonymous"))
}

func TestProvisionLimit_PaidTiersUnlimited(t *testing.T) {
	r := plans.Default()
	for _, tier := range []string{"hobby", "pro", "team", "growth"} {
		assert.Equal(t, -1, r.ProvisionLimit(tier),
			"ProvisionLimit(%q) must be -1 (unlimited)", tier)
	}
}

func TestLoad_ValidFile_ReturnsRegistry(t *testing.T) {
	yaml := `
plans:
  anonymous:
    display_name: "Anon"
    price_monthly_cents: 0
    trial_days: 0
    limits:
      provisions_per_day: 3
      postgres_storage_mb: 10
      redis_memory_mb: 5
    features:
      alerts: false
      custom_domains: false
      sla: false
promotions: []
`
	path := writeTempYAML(t, yaml)
	r, err := plans.Load(path)
	require.NoError(t, err)
	assert.Equal(t, 3, r.ProvisionLimit("anonymous"))
}

func TestLoad_MissingFile_ReturnsError(t *testing.T) {
	_, err := plans.Load("/nonexistent/plans.yaml")
	assert.Error(t, err)
}

func TestLoad_MissingAnonymousPlan_ReturnsError(t *testing.T) {
	yaml := `
plans:
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits:
      provisions_per_day: -1
      postgres_storage_mb: 5120
      redis_memory_mb: 256
    features:
      alerts: true
      custom_domains: false
      sla: false
promotions: []
`
	path := writeTempYAML(t, yaml)
	_, err := plans.Load(path)
	assert.ErrorContains(t, err, "anonymous", "missing anonymous plan must return descriptive error")
}

func TestLoad_InvalidYAML_ReturnsError(t *testing.T) {
	path := writeTempYAML(t, "plans: [this is: not: valid: yaml}")
	_, err := plans.Load(path)
	assert.Error(t, err)
}

func TestAll_ReturnsAllPlans(t *testing.T) {
	r := plans.Default()
	all := r.All()
	assert.Len(t, all, 6, "default registry must have 6 plans (anonymous, free, hobby, pro, team, growth)")
	for _, name := range []string{"anonymous", "free", "hobby", "pro", "team", "growth"} {
		assert.Contains(t, all, name)
	}
}

// TestFreeTier_MirrorsAnonymous verifies the api-level plans wrapper exposes
// the new `free` tier and that its limits are byte-for-byte identical to
// `anonymous`. The two tiers must stay in lock-step so an `anonymous` ->
// `free` flip at claim time can't accidentally widen or narrow quotas.
func TestFreeTier_MirrorsAnonymous(t *testing.T) {
	r := plans.Default()
	anon := r.Get("anonymous")
	free := r.Get("free")
	require.NotNil(t, free)
	assert.Equal(t, "free", free.Name)
	assert.Equal(t, anon.Limits, free.Limits,
		"free tier limits must mirror anonymous exactly")
	assert.Equal(t, anon.Features, free.Features,
		"free tier features must mirror anonymous exactly")
	// The two registry lookups must also agree across every per-service helper.
	for _, svc := range []string{"postgres", "redis", "mongodb", "queue", "storage", "webhook"} {
		assert.Equal(t,
			r.StorageLimitMB("anonymous", svc),
			r.StorageLimitMB("free", svc),
			"StorageLimitMB(free,%s) must equal anonymous", svc)
	}
	assert.Equal(t, r.ProvisionLimit("anonymous"), r.ProvisionLimit("free"),
		"ProvisionLimit(free) must equal anonymous")
}

func TestValidatePromotion_ValidCode_ReturnsPromotion(t *testing.T) {
	yaml := `
plans:
  anonymous:
    display_name: "Anon"
    price_monthly_cents: 0
    trial_days: 0
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits: {provisions_per_day: -1, postgres_storage_mb: 5120, redis_memory_mb: 256}
    features: {alerts: true, custom_domains: false, sla: false}
promotions:
  - code: "SAVE20"
    discount_percent: 20
    applies_to: ["pro"]
    expires_at: ""
    max_uses: -1
    description: "20% off Pro"
`
	path := writeTempYAML(t, yaml)
	r, err := plans.Load(path)
	require.NoError(t, err)

	promo, err := r.ValidatePromotion("SAVE20", "pro")
	require.NoError(t, err)
	assert.Equal(t, 20, promo.DiscountPercent)
}

func TestValidatePromotion_CaseInsensitive(t *testing.T) {
	yaml := `
plans:
  anonymous:
    display_name: "Anon"
    price_monthly_cents: 0
    trial_days: 0
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits: {provisions_per_day: -1, postgres_storage_mb: 5120, redis_memory_mb: 256}
    features: {alerts: true, custom_domains: false, sla: false}
promotions:
  - code: "LAUNCH"
    discount_percent: 50
    applies_to: ["pro"]
    expires_at: ""
    max_uses: -1
    description: "Launch discount"
`
	path := writeTempYAML(t, yaml)
	r, err := plans.Load(path)
	require.NoError(t, err)

	_, err = r.ValidatePromotion("launch", "pro") // lowercase
	assert.NoError(t, err, "promotion codes must be case-insensitive")
}

func TestValidatePromotion_UnknownCode_ReturnsError(t *testing.T) {
	r := plans.Default()
	_, err := r.ValidatePromotion("DOESNOTEXIST", "pro")
	assert.Error(t, err)
}

func TestValidatePromotion_WrongPlan_ReturnsError(t *testing.T) {
	yaml := `
plans:
  anonymous:
    display_name: "Anon"
    price_monthly_cents: 0
    trial_days: 0
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits: {provisions_per_day: -1, postgres_storage_mb: 5120, redis_memory_mb: 256}
    features: {alerts: true, custom_domains: false, sla: false}
promotions:
  - code: "PROONLY"
    discount_percent: 10
    applies_to: ["pro"]
    expires_at: ""
    max_uses: -1
    description: "Pro only"
`
	path := writeTempYAML(t, yaml)
	r, err := plans.Load(path)
	require.NoError(t, err)

	_, err = r.ValidatePromotion("PROONLY", "anonymous")
	assert.Error(t, err, "promotion for 'pro' must not apply to 'anonymous'")
}

func TestLoad_PlansYAMLFile_MatchesDefaults(t *testing.T) {
	// Verify that the actual plans.yaml in the repo loads cleanly and that
	// its anonymous limits match the built-in defaults. This catches accidental
	// drift between the file and the Default() function.
	repoRoot := filepath.Join("..", "..", "plans.yaml")
	if _, err := os.Stat(repoRoot); os.IsNotExist(err) {
		t.Skip("plans.yaml not found in repo root — skipping file consistency check")
	}

	fromFile, err := plans.Load(repoRoot)
	require.NoError(t, err)

	fromDefault := plans.Default()
	assert.Equal(t, fromDefault.ProvisionLimit("anonymous"), fromFile.ProvisionLimit("anonymous"),
		"plans.yaml anonymous provision limit must match Default()")
}

// writeTempYAML writes content to a temp file and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "plans-*.yaml")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}
