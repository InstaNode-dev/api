package handlers_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/plans"
)

// capabilitiesResp mirrors the contract-stable response shape so the test
// can assert on individual fields without unmarshalling into the unexported
// handler-local struct.
type capabilitiesResp struct {
	OK      bool             `json:"ok"`
	Tiers   []capabilityTier `json:"tiers"`
	Docs    string           `json:"docs"`
	Contact string           `json:"contact"`
}

type capabilityTier struct {
	Tier                  string         `json:"tier"`
	DisplayName           string         `json:"display_name"`
	PriceUSDMonthly       int            `json:"price_usd_monthly"`
	PaidFromDayOne        bool           `json:"paid_from_day_one"`
	StorageLimitMB        map[string]int `json:"storage_limit_mb"`
	ConnectionsLimit      map[string]int `json:"connections_limit"`
	Deployments           int            `json:"deployments_apps"`
	BackupRetentionDays   int            `json:"backup_retention_days"`
	BackupRestoreEnabled  bool           `json:"backup_restore_enabled"`
	ManualBackupsPerDay   int            `json:"manual_backups_per_day"`
	AnnualDiscountPercent int            `json:"annual_discount_percent"`
	UpgradeURL            string         `json:"upgrade_url"`
}

// newCapabilitiesApp wires a minimal Fiber app with the /capabilities
// route bound to the given plan registry. Keeps each test self-contained
// instead of spinning up the full router (which would drag in DB + redis
// + middleware that this handler doesn't depend on).
func newCapabilitiesApp(t *testing.T, reg *plans.Registry) *fiber.App {
	t.Helper()
	// respondError returns ErrResponseWritten as a sentinel after writing
	// the body — fiber's default error handler then double-writes a plain
	// "Internal Server Error" string, which breaks JSON decoding in tests.
	// Mirror the same handler shape used by the production router so the
	// body that landed in the response is what the test reads back.
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	h := handlers.NewCapabilitiesHandler(reg)
	app.Get("/api/v1/capabilities", h.Get)
	return app
}

// callCapabilities issues GET /api/v1/capabilities against the app and
// decodes the response. Centralised so individual tests don't repeat the
// httptest plumbing.
func callCapabilities(t *testing.T, app *fiber.App) (int, capabilitiesResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err, "app.Test failed")
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read body failed")
	var out capabilitiesResp
	if len(body) > 0 {
		require.NoError(t, json.Unmarshal(body, &out), "unmarshal failed: %s", string(body))
	}
	return resp.StatusCode, out
}

// TestCapabilities_IteratesPlansYAML — the core W12 contract. Loads a
// fixture registry containing 7 known monthly tiers (anonymous, free,
// hobby, hobby_plus, pro, growth, team) PLUS one synthetic unranked tier.
// The handler must:
//
//  1. Surface all 7 known tiers (zero-config — no hardcoded slice).
//  2. Sort them by plans.Rank ascending (anonymous → team).
//  3. Drop the unranked tier (rank == -1).
//  4. NOT surface yearly variants (the fixture has none, but a follow-up
//     test pins that contract directly).
//
// This locks the "plans.yaml is the source of truth" guarantee — adding a
// tier to plans.yaml + rank.go is sufficient; capabilities.go does not
// need a corresponding edit.
func TestCapabilities_IteratesPlansYAML(t *testing.T) {
	path := filepath.Join("testdata", "plans-with-extra-tier.yaml")
	reg, err := plans.Load(path)
	require.NoError(t, err, "load fixture")

	app := newCapabilitiesApp(t, reg)
	status, body := callCapabilities(t, app)

	require.Equal(t, http.StatusOK, status, "expected 200 OK")
	require.True(t, body.OK, "expected ok=true")

	// Expected: 7 known monthly tiers in rank order. The unranked
	// "test_tier" entry in the fixture must be dropped.
	wantOrder := []string{"anonymous", "free", "hobby", "hobby_plus", "pro", "growth", "team"}
	require.Len(t, body.Tiers, len(wantOrder),
		"expected %d tiers (unranked test_tier should be dropped), got %d: %v",
		len(wantOrder), len(body.Tiers), tierNames(body.Tiers))

	for i, want := range wantOrder {
		assert.Equal(t, want, body.Tiers[i].Tier,
			"tier at position %d (rank %d): want %q got %q",
			i, plans.Rank(want), want, body.Tiers[i].Tier)
	}

	// Locked envelope fields — frontends key off these.
	assert.Equal(t, "https://instanode.dev/llms-full.txt", body.Docs)
	assert.Equal(t, "mailto:enterprise@instanode.dev", body.Contact)
}

// TestCapabilities_DerivesPriceFromPlanRegistry verifies the per-row
// pricing data is read out of the plan, not the old hardcoded slice.
// Confirms the cents→dollars conversion (plans.yaml stores cents).
func TestCapabilities_DerivesPriceFromPlanRegistry(t *testing.T) {
	path := filepath.Join("testdata", "plans-with-extra-tier.yaml")
	reg, err := plans.Load(path)
	require.NoError(t, err, "load fixture")

	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)

	// Build a tier-keyed map for direct assertions. Each price comes
	// straight from the YAML (cents/100).
	byTier := map[string]capabilityTier{}
	for _, t := range body.Tiers {
		byTier[t.Tier] = t
	}

	cases := []struct {
		tier         string
		wantPriceUSD int
		wantPaid     bool
		wantDisplay  string
	}{
		{"anonymous", 0, false, "Anonymous"},
		{"free", 0, false, "Free"},
		{"hobby", 9, true, "Hobby"},
		{"hobby_plus", 19, true, "Hobby Plus"},
		{"growth", 99, true, "Growth"},
		{"pro", 49, true, "Pro"},
		{"team", 199, true, "Team"},
	}
	for _, c := range cases {
		got, ok := byTier[c.tier]
		require.True(t, ok, "missing tier %q in response", c.tier)
		assert.Equal(t, c.wantPriceUSD, got.PriceUSDMonthly, "%s price_usd_monthly", c.tier)
		assert.Equal(t, c.wantPaid, got.PaidFromDayOne, "%s paid_from_day_one", c.tier)
		assert.Equal(t, c.wantDisplay, got.DisplayName, "%s display_name", c.tier)
		assert.Equal(t, "https://instanode.dev/pricing/", got.UpgradeURL, "%s upgrade_url", c.tier)
	}
}

// TestCapabilities_LimitsResolveFromRegistry — spot-checks that the
// per-tier limit maps come from the registry's resolution methods, not
// any cached state. Hobby Plus is the W11 tier added after the original
// capabilities slice — pre-W12 it returned an empty/zero limits map
// because the hardcoded slice predated it.
func TestCapabilities_LimitsResolveFromRegistry(t *testing.T) {
	path := filepath.Join("testdata", "plans-with-extra-tier.yaml")
	reg, err := plans.Load(path)
	require.NoError(t, err, "load fixture")

	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)

	var hp *capabilityTier
	for i := range body.Tiers {
		if body.Tiers[i].Tier == "hobby_plus" {
			hp = &body.Tiers[i]
			break
		}
	}
	require.NotNil(t, hp, "hobby_plus missing from response")

	// Hobby Plus fixture limits (mirror plans.yaml).
	assert.Equal(t, 1024, hp.StorageLimitMB["postgres"], "hobby_plus postgres storage")
	assert.Equal(t, 5120, hp.StorageLimitMB["storage"], "hobby_plus object storage")
	assert.Equal(t, 50, hp.StorageLimitMB["redis"], "hobby_plus redis memory")
	assert.Equal(t, 8, hp.ConnectionsLimit["postgres"], "hobby_plus postgres conns")
	assert.Equal(t, 2, hp.Deployments, "hobby_plus deployments")
	assert.Equal(t, 14, hp.BackupRetentionDays, "hobby_plus backup retention")
	assert.True(t, hp.BackupRestoreEnabled, "hobby_plus backup restore")
	assert.Equal(t, 5, hp.ManualBackupsPerDay, "hobby_plus manual backups/day")
}

// TestCapabilities_PlansUnavailable — when the registry pointer is nil
// (boot-time failure in dev with no fallback), the handler must return
// 503 instead of panicking. Lifted contract from the original handler.
func TestCapabilities_PlansUnavailable(t *testing.T) {
	app := newCapabilitiesApp(t, nil)
	status, body := callCapabilities(t, app)
	require.Equal(t, http.StatusServiceUnavailable, status)
	assert.False(t, body.OK)
}

// TestCapabilities_SkipsYearlyVariants — the production registry contains
// hobby_yearly, hobby_plus_yearly, pro_yearly, team_yearly. These share
// limits with the canonical tier and would create duplicate rows in the
// /capabilities matrix. Using plans.Default() (which mirrors the prod
// YAML) confirms the filter holds against the real shape.
func TestCapabilities_SkipsYearlyVariants(t *testing.T) {
	reg := plans.Default()
	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)

	for _, tr := range body.Tiers {
		assert.NotContains(t, tr.Tier, "_yearly",
			"yearly variant %q must not appear in /capabilities", tr.Tier)
	}

	// And the canonical tiers ARE present in the expected rank order.
	wantOrder := []string{"anonymous", "free", "hobby", "hobby_plus", "pro", "growth", "team"}
	require.Len(t, body.Tiers, len(wantOrder),
		"plans.Default() should produce %d monthly tiers, got %d (%v)",
		len(wantOrder), len(body.Tiers), tierNames(body.Tiers))
	for i, want := range wantOrder {
		assert.Equal(t, want, body.Tiers[i].Tier, "position %d", i)
	}
}

// TestCapabilities_AnnualDiscountFromYAML — when a {tier}_yearly variant
// exists in the registry, the canonical tier reports a non-zero
// annual_discount_percent computed from (1 - yearly/(monthly*12)).
// plans.Default() carries the production yearly prices, so this pins
// against shipped numbers.
func TestCapabilities_AnnualDiscountFromYAML(t *testing.T) {
	reg := plans.Default()
	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)

	byTier := map[string]capabilityTier{}
	for _, t := range body.Tiers {
		byTier[t.Tier] = t
	}

	// Free + anonymous have no yearly variant (price_monthly = 0) so
	// discount must be 0.
	assert.Equal(t, 0, byTier["anonymous"].AnnualDiscountPercent, "anonymous discount")
	assert.Equal(t, 0, byTier["free"].AnnualDiscountPercent, "free discount")

	// Hobby: $9 x 12 = $108, yearly = $99. saved = $9. pct = 9/108 ≈ 8%.
	assert.Equal(t, 8, byTier["hobby"].AnnualDiscountPercent, "hobby discount")
	// Pro: $49 x 12 = $588, yearly = $490. saved = $98. pct = 98/588 ≈ 17%.
	assert.Equal(t, 17, byTier["pro"].AnnualDiscountPercent, "pro discount")
	// Team: $199 x 12 = $2388, yearly = $1990. saved = $398. pct ≈ 17%.
	assert.Equal(t, 17, byTier["team"].AnnualDiscountPercent, "team discount")
}

// tierNames extracts just the tier identifiers from a slice of rows for
// readable assertion failure messages.
func tierNames(rows []capabilityTier) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Tier
	}
	return out
}
