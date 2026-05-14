package handlers

import (
	"sort"

	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/plans"
)

// CapabilitiesHandler — GET /api/v1/capabilities.
//
// Returns the full tier matrix as JSON so AI agents can discover
// "what can I do at which tier" without provisioning-and-failing or
// scraping llms.txt. Surfaced as task #8 in the persona-1 (autonomous
// agent) friction report.
//
// Public, unauthenticated. The response shape is contract-stable.
//
// Zero-config tier addition: this handler iterates the live plans
// registry, so adding a tier in api/plans.yaml automatically surfaces it
// here without touching any Go code. The previous implementation kept a
// hardcoded slice of known tiers which silently dropped any tier not in
// the slice — a footgun that bit hobby_plus before W12. The contract is
// now: if plans.yaml has it (and rank.go ranks it), /capabilities returns it.
type CapabilitiesHandler struct {
	plans *plans.Registry
}

func NewCapabilitiesHandler(p *plans.Registry) *CapabilitiesHandler {
	return &CapabilitiesHandler{plans: p}
}

type tierCapabilities struct {
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
	// RPOMinutes / RTOMinutes — FIX-H #Q50 (B36). 0 means
	// "not promised" (no scheduled backups / no self-serve restore on
	// the tier). Lets an agent reason about durability requirements
	// per-tier without a second round-trip.
	RPOMinutes            int            `json:"rpo_minutes"`
	RTOMinutes            int            `json:"rto_minutes"`
	AnnualDiscountPercent int            `json:"annual_discount_percent"`
	UpgradeURL            string         `json:"upgrade_url"`
}

// capabilityResourceTypes is the list of service types the /capabilities
// matrix reports storage + connection limits for. Order is contract-
// stable — frontends iterate the response and key by this string set.
var capabilityResourceTypes = []string{
	"postgres", "redis", "mongodb", "queue", "storage", "webhook", "vector",
}

// upgradeURL is the marketing pricing page that every tier row in the
// /capabilities response points back to. Hoisted to a package const so
// the URL fragment isn't scattered as a string literal across the handler.
const upgradeURL = "https://instanode.dev/pricing/"

// docsURL is the LLM-targeted docs surface returned in the /capabilities
// envelope. Same rationale as upgradeURL — single source for the string.
const docsURL = "https://instanode.dev/llms-full.txt"

// supportContact is the mailto: link returned in the /capabilities envelope.
const supportContact = "mailto:enterprise@instanode.dev"

// Get implements GET /api/v1/capabilities.
//
// Iterates the live plans registry (h.plans.All()) so adding a tier in
// plans.yaml automatically appears here. Output is sorted by plans.Rank
// ascending (anonymous=0 → team=6) so consumers see tiers in upgrade
// order. *_yearly variants are excluded — the canonical monthly tier
// already represents that capability bundle and the yearly variant only
// differs in billing period + price.
func (h *CapabilitiesHandler) Get(c *fiber.Ctx) error {
	if h.plans == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "plans_unavailable", "Tier matrix not loaded")
	}

	all := h.plans.All()

	// Filter to monthly tiers with a known rank. Unknown tiers (rank == -1)
	// are dropped intentionally: an unranked tier name has no defined
	// position in the upgrade ladder, which would corrupt the sorted
	// output. plans.yaml additions should also add a Rank entry in
	// common/plans/rank.go so the new tier surfaces here.
	type entry struct {
		name string
		plan *plans.Plan
		rank int
	}
	entries := make([]entry, 0, len(all))
	for name, p := range all {
		if p == nil {
			continue
		}
		// Skip *_yearly variants — they share limits with the canonical tier
		// and only differ in billing cycle. The /capabilities matrix reports
		// per-tier capabilities, not per-billing-cycle pricing.
		if p.BillingPeriod == "yearly" {
			continue
		}
		r := plans.Rank(name)
		if r < 0 {
			// Unranked tier — silently drop. Adding a rank entry in
			// common/plans/rank.go is the gate for new tiers to surface
			// here. Silent-drop is the right call so a rogue YAML edit
			// doesn't 500 /capabilities; an unranked tier in production
			// is caught by the rank_test.go invariant.
			continue
		}
		entries = append(entries, entry{name: name, plan: p, rank: r})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].rank != entries[j].rank {
			return entries[i].rank < entries[j].rank
		}
		// Deterministic tie-breaker by name — ensures byte-identical JSON
		// between runs even if two tiers ever share a rank.
		return entries[i].name < entries[j].name
	})

	out := make([]tierCapabilities, 0, len(entries))
	for _, e := range entries {
		storage := map[string]int{}
		conns := map[string]int{}
		for _, rt := range capabilityResourceTypes {
			storage[rt] = h.plans.StorageLimitMB(e.name, rt)
			conns[rt] = h.plans.ConnectionsLimit(e.name, rt)
		}
		priceUSD := e.plan.PriceMonthly / 100 // cents → dollars
		out = append(out, tierCapabilities{
			Tier:                  e.name,
			DisplayName:           e.plan.DisplayName,
			PriceUSDMonthly:       priceUSD,
			PaidFromDayOne:        priceUSD > 0,
			StorageLimitMB:        storage,
			ConnectionsLimit:      conns,
			Deployments:           h.plans.DeploymentsAppsLimit(e.name),
			BackupRetentionDays:   h.plans.BackupRetentionDays(e.name),
			BackupRestoreEnabled:  h.plans.BackupRestoreEnabled(e.name),
			ManualBackupsPerDay:   h.plans.ManualBackupsPerDay(e.name),
			RPOMinutes:            h.plans.RPOMinutes(e.name),
			RTOMinutes:            h.plans.RTOMinutes(e.name),
			AnnualDiscountPercent: annualDiscountPercent(all, e.name),
			UpgradeURL:            upgradeURL,
		})
	}

	return c.JSON(fiber.Map{
		"ok":      true,
		"tiers":   out,
		"docs":    docsURL,
		"contact": supportContact,
	})
}

// annualDiscountPercent computes the percent discount of the {tier}_yearly
// variant vs 12x the monthly tier. Returns 0 if either side is missing or
// the monthly price is 0 (free tier). Rounds to the nearest whole percent.
//
// Annual prices are stored as the full-year amount in cents (see
// common/plans/plans.go — "for yearly variants this stores the *annual*
// price in cents"). The math is:
//
//	discount = 1 - (annual / (monthly * 12))
//
// Free tiers (price_monthly_cents == 0) return 0 — there's nothing to
// discount. Missing yearly variants also return 0 — the tier just has no
// annual offering.
func annualDiscountPercent(all map[string]*plans.Plan, tier string) int {
	monthly, ok := all[tier]
	if !ok || monthly == nil || monthly.PriceMonthly == 0 {
		return 0
	}
	yearly, ok := all[tier+"_yearly"]
	if !ok || yearly == nil || yearly.PriceMonthly == 0 {
		return 0
	}
	twelveX := monthly.PriceMonthly * 12
	if twelveX <= 0 {
		return 0
	}
	saved := twelveX - yearly.PriceMonthly
	if saved <= 0 {
		return 0
	}
	// Round to nearest whole percent: (saved * 100 + half) / twelveX.
	pct := (saved*100 + twelveX/2) / twelveX
	return pct
}

// IncidentsHandler — GET /api/v1/incidents.
//
// Returns an empty list today. The dashboard's W7-A IncidentsPage calls
// this endpoint and tolerates 404; this handler upgrades the contract so
// the page renders cleanly and future incident-tracking can populate the
// same response without a schema break.
type IncidentsHandler struct{}

func NewIncidentsHandler() *IncidentsHandler { return &IncidentsHandler{} }

// incidentItem is the per-row response shape. Reserved fields documented
// inline so a future incident-feed worker can populate them without a
// schema break.
type incidentItem struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Severity   string `json:"severity"`   // info | minor | major | critical
	Status     string `json:"status"`     // investigating | identified | monitoring | resolved
	StartedAt  string `json:"started_at"` // ISO8601
	ResolvedAt string `json:"resolved_at,omitempty"`
	Summary    string `json:"summary"`
	URL        string `json:"url,omitempty"`
}

func (h *IncidentsHandler) List(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"ok":          true,
		"items":       []incidentItem{},
		"total":       0,
		"status_page": "https://instanode.dev/status/",
	})
}
