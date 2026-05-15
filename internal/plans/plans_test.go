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
	// 7 base tiers + 4 yearly variants (hobby_yearly, hobby_plus_yearly,
	// pro_yearly, team_yearly) = 11. W11 (2026-05-13) added hobby_plus
	// + hobby_plus_yearly as the $19/mo mid-step between hobby and pro.
	assert.Len(t, all, 11, "default registry must have 11 plans (7 base + 4 yearly variants)")
	for _, name := range []string{
		"anonymous", "free", "hobby", "hobby_plus", "pro", "team", "growth",
		"hobby_yearly", "hobby_plus_yearly", "pro_yearly", "team_yearly",
	} {
		assert.Contains(t, all, name)
	}
}

// TestYearlyVariants_MirrorMonthly ensures the api-level wrapper exposes
// the new yearly tiers with limits + features identical to their monthly
// counterparts. The only allowed divergence is price and billing_period.
func TestYearlyVariants_MirrorMonthly(t *testing.T) {
	r := plans.Default()
	for _, base := range []string{"hobby", "hobby_plus", "pro", "team"} {
		yearly := r.Get(base + "_yearly")
		monthly := r.Get(base)
		assert.Equal(t, monthly.Limits, yearly.Limits,
			"%s_yearly limits must mirror %s", base, base)
		assert.Equal(t, monthly.Features, yearly.Features,
			"%s_yearly features must mirror %s", base, base)
		assert.Equal(t, "yearly", yearly.BillingPeriod,
			"%s_yearly must declare billing_period: yearly", base)
	}
}

// TestCanonicalTier_StripsYearlySuffix verifies the re-exported helper.
func TestCanonicalTier_StripsYearlySuffix(t *testing.T) {
	assert.Equal(t, "pro", plans.CanonicalTier("pro_yearly"))
	assert.Equal(t, "hobby", plans.CanonicalTier("hobby_yearly"))
	assert.Equal(t, "hobby_plus", plans.CanonicalTier("hobby_plus_yearly"))
	assert.Equal(t, "team", plans.CanonicalTier("team_yearly"))
	assert.Equal(t, "pro", plans.CanonicalTier("pro"))
	assert.Equal(t, "hobby_plus", plans.CanonicalTier("hobby_plus"))
	assert.Equal(t, "anonymous", plans.CanonicalTier("anonymous"))
	assert.Equal(t, "", plans.CanonicalTier(""))
}

// TestHobbyPlus_TierMatrix is the W11 lock-in test for the api-level
// wrapper: hobby_plus exists with the expected limits + features.
// Mirrors the common-package test of the same name; this one exercises
// the api re-export path so a future drift between the two packages
// is caught at the api layer too.
func TestHobbyPlus_TierMatrix(t *testing.T) {
	r := plans.Default()
	require.NotNil(t, r)
	// PriceMonthly: $19 = 1900 cents.
	assert.Equal(t, 1900, r.PriceMonthly("hobby_plus"),
		"hobby_plus must be priced at $19/mo (1900 cents)")
	// Display name surfaces in dashboard + invoices.
	assert.Equal(t, "Hobby Plus", r.DisplayName("hobby_plus"))
	// Headline feature: 2 deployment apps + custom domains.
	assert.Equal(t, 2, r.DeploymentsAppsLimit("hobby_plus"),
		"hobby_plus must allow 2 deployment apps")
	assert.True(t, r.CustomDomainsAllowed("hobby_plus"),
		"hobby_plus must enable custom_domains (the W11 headline feature)")
	// 2026-05-15 (W12 pricing pass): hobby_plus rolled back to
	// production-only — multi-env is now Pro+ only (see
	// multiEnvTierAllowed in api/internal/handlers/stack.go).
	// Coverage gap: the common/plans_test.go peer was updated when
	// the rollback shipped but this api wrapper test was missed —
	// classic single-site-fallacy. CLAUDE.md rule 16 added afterward.
	assert.Equal(t, 50, r.VaultMaxEntries("hobby_plus"))
	assert.Equal(t, []string{"production"},
		r.VaultEnvsAllowed("hobby_plus"),
		"hobby_plus is production-only post 2026-05-15; Pro is the multi-env unlock")
	// Storage / connection limits — mirror hobby on cheap services, bump
	// mongodb + object storage to mid-tier values.
	assert.Equal(t, 1024, r.StorageLimitMB("hobby_plus", "postgres"))
	assert.Equal(t, 50, r.StorageLimitMB("hobby_plus", "redis"))
	assert.Equal(t, 1024, r.StorageLimitMB("hobby_plus", "mongodb"))
	assert.Equal(t, 5120, r.StorageLimitMB("hobby_plus", "storage"))
	assert.Equal(t, 5000, r.StorageLimitMB("hobby_plus", "webhook"))
	assert.Equal(t, 8, r.ConnectionsLimit("hobby_plus", "postgres"))
	assert.Equal(t, 5, r.ConnectionsLimit("hobby_plus", "mongodb"))
	// Backup posture: 14-day retention, restore enabled (mid-tier
	// between hobby's 7-day-no-restore and pro's 30-day-with-restore).
	assert.Equal(t, 14, r.BackupRetentionDays("hobby_plus"))
	assert.True(t, r.BackupRestoreEnabled("hobby_plus"),
		"hobby_plus is the cheapest tier with self-serve restore")
	assert.Equal(t, 5, r.ManualBackupsPerDay("hobby_plus"))
	// Yearly variant exists and is cheaper than monthly x12.
	yearly := r.Get("hobby_plus_yearly")
	require.NotNil(t, yearly)
	assert.Equal(t, 19900, yearly.PriceMonthly, "hobby_plus_yearly = $199/yr (19900 cents)")
	assert.Less(t, yearly.PriceMonthly, 1900*12,
		"hobby_plus_yearly must be cheaper than 12x monthly so the savings claim is honest")
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
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
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
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
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
    limits: {provisions_per_day: 5, postgres_storage_mb: 10, redis_memory_mb: 5}
    features: {alerts: false, custom_domains: false, sla: false}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
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
