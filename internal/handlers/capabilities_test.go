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
	ResourceCountLimit    map[string]int `json:"resource_count_limit"`
	Deployments           int            `json:"deployments_apps"`
	BackupRetentionDays   int            `json:"backup_retention_days"`
	BackupRestoreEnabled  bool           `json:"backup_restore_enabled"`
	ManualBackupsPerDay   int            `json:"manual_backups_per_day"`
	AnnualDiscountPercent int            `json:"annual_discount_percent"`
	// DOG-26: UpgradeURL is *string — terminal tier (Team) emits null.
	UpgradeURL     *string `json:"upgrade_url"`
	IsTerminalTier bool    `json:"is_terminal_tier"`
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
		// DOG-26: terminal tier (Team — top of the rank ladder) emits
		// upgrade_url=null + is_terminal_tier=true. Every other tier
		// emits the pricing URL.
		if c.tier == "team" {
			assert.Nil(t, got.UpgradeURL, "%s upgrade_url must be null (terminal tier)", c.tier)
			assert.True(t, got.IsTerminalTier, "%s is_terminal_tier must be true", c.tier)
		} else {
			require.NotNil(t, got.UpgradeURL, "%s upgrade_url must be non-null", c.tier)
			assert.Equal(t, "https://instanode.dev/pricing/", *got.UpgradeURL, "%s upgrade_url", c.tier)
			assert.False(t, got.IsTerminalTier, "%s is_terminal_tier must be false (non-terminal)", c.tier)
		}
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

// TestCapabilities_SurfacesResourceCountLimit is the Task #55 rule-18 surface
// guard: GET /api/v1/capabilities must expose resource_count_limit for EVERY
// count-capped service on every paid tier, with the value matching the live
// registry. Iterates the registry rather than hand-typing tiers so a new tier or
// service can't silently ship without the cap appearing on the public matrix.
func TestCapabilities_SurfacesResourceCountLimit(t *testing.T) {
	reg := plans.Default()
	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)
	require.NotEmpty(t, body.Tiers)

	countServices := []string{"postgres", "vector", "redis", "mongodb", "storage", "queue"}
	for _, tier := range body.Tiers {
		require.NotNil(t, tier.ResourceCountLimit,
			"tier %q must carry resource_count_limit", tier.Tier)
		for _, svc := range countServices {
			got, ok := tier.ResourceCountLimit[svc]
			require.True(t, ok, "tier %q resource_count_limit must include %q", tier.Tier, svc)
			assert.Equal(t, reg.ResourceCountLimit(tier.Tier, svc), got,
				"tier %q %s count limit must match the registry", tier.Tier, svc)
		}
		// Webhook is request-capped, not count-capped — must NOT appear.
		_, hasWebhook := tier.ResourceCountLimit["webhook"]
		assert.False(t, hasWebhook, "webhook must not appear in resource_count_limit (it is request-capped)")
	}

	// Spot-pin a couple of binding values so a loosened cap is a visible diff.
	for _, tier := range body.Tiers {
		switch tier.Tier {
		case "pro":
			assert.Equal(t, 3, tier.ResourceCountLimit["redis"], "pro redis_count")
			assert.Equal(t, 5, tier.ResourceCountLimit["postgres"], "pro postgres_count")
		case "team":
			assert.Equal(t, 4, tier.ResourceCountLimit["redis"], "team redis_count")
		}
	}
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

// TestCapabilities_TerminalTierUpgradeURLIsNull pins DOG-26: the top tier
// in the rank ladder (Team today) emits upgrade_url=null + is_terminal_tier=
// true. Every non-terminal tier emits the pricing URL + is_terminal_tier=false.
//
// Registry-iterating per CLAUDE.md rule 18: tomorrow's plans.yaml + rank.go
// addition (e.g. an `enterprise` tier above team) automatically shifts the
// terminal marker — this test reads the live rank ordering rather than
// hardcoding "team" as the terminal name, so adding a new top tier doesn't
// require touching this assertion.
func TestCapabilities_TerminalTierUpgradeURLIsNull(t *testing.T) {
	reg := plans.Default()
	app := newCapabilitiesApp(t, reg)
	_, body := callCapabilities(t, app)
	require.NotEmpty(t, body.Tiers, "expected at least one tier")

	// Last row in the rank-sorted slice is the terminal tier by
	// construction (capabilities.go sorts entries by rank ascending).
	terminal := body.Tiers[len(body.Tiers)-1]
	assert.True(t, terminal.IsTerminalTier,
		"DOG-26: top-of-ladder tier (%q) must have is_terminal_tier=true", terminal.Tier)
	assert.Nil(t, terminal.UpgradeURL,
		"DOG-26: top-of-ladder tier (%q) must have upgrade_url=null — nothing to upgrade to", terminal.Tier)

	// Every other row must be non-terminal with a populated URL.
	for _, tr := range body.Tiers[:len(body.Tiers)-1] {
		assert.False(t, tr.IsTerminalTier,
			"DOG-26: non-terminal tier %q must have is_terminal_tier=false", tr.Tier)
		require.NotNil(t, tr.UpgradeURL,
			"DOG-26: non-terminal tier %q must have a non-null upgrade_url", tr.Tier)
		assert.Equal(t, "https://instanode.dev/pricing/", *tr.UpgradeURL,
			"non-terminal tier %q upgrade_url", tr.Tier)
	}
}

// TestCapabilities_CacheControlPublicMaxAge60 pins BUG-API-039 /
// BUG-API-311: /api/v1/capabilities is dashboard-hit on every nav
// (sidebar tiles, billing card, settings) and the tier matrix is
// immutable for the life of the running pod (only changes on a
// plans.yaml edit + redeploy). Without a Cache-Control hint each nav
// re-fetched the full ~4 KB matrix; sidebar fanout meant 4-6 redundant
// fetches per nav (BUG-DASH-016).
//
// Pin `public, max-age=60, must-revalidate` so the browser/edge cache
// serves the matrix for a minute while still re-validating on expiry.
// A future deletion of the c.Set call fails this assertion before merge.
func TestCapabilities_CacheControlPublicMaxAge60(t *testing.T) {
	reg := plans.Default()
	app := newCapabilitiesApp(t, reg)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "public, max-age=60, must-revalidate",
		resp.Header.Get("Cache-Control"),
		"BUG-API-039/311: /api/v1/capabilities must stamp Cache-Control: public, max-age=60, must-revalidate so dashboard nav fanout doesn't re-fetch the same immutable matrix every navigation")
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

	// Hobby: $9 x 12 = $108, yearly = $90. saved = $18. pct = 18/108 ≈ 17%.
	assert.Equal(t, 17, byTier["hobby"].AnnualDiscountPercent, "hobby discount")
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
