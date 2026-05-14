package handlers

import (
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
	AnnualDiscountPercent int            `json:"annual_discount_percent"`
	UpgradeURL            string         `json:"upgrade_url"`
}

// Get implements GET /api/v1/capabilities.
func (h *CapabilitiesHandler) Get(c *fiber.Ctx) error {
	if h.plans == nil {
		return respondError(c, fiber.StatusServiceUnavailable, "plans_unavailable", "Tier matrix not loaded")
	}

	resourceTypes := []string{"postgres", "redis", "mongodb", "queue", "storage", "webhook", "vector"}
	tiers := []struct {
		key, displayName string
		priceUSD         int
		annualPct        int
	}{
		{"anonymous", "Anonymous (24h TTL)", 0, 0},
		{"free", "Free (claimed sandbox)", 0, 0},
		{"hobby", "Hobby", 9, 8},
		{"pro", "Pro", 49, 17},
		{"growth", "Growth", 99, 17},
		{"team", "Team", 199, 17},
	}

	out := make([]tierCapabilities, 0, len(tiers))
	for _, t := range tiers {
		storage := map[string]int{}
		conns := map[string]int{}
		for _, rt := range resourceTypes {
			storage[rt] = h.plans.StorageLimitMB(t.key, rt)
			conns[rt] = h.plans.ConnectionsLimit(t.key, rt)
		}
		out = append(out, tierCapabilities{
			Tier:                  t.key,
			DisplayName:           t.displayName,
			PriceUSDMonthly:       t.priceUSD,
			PaidFromDayOne:        t.priceUSD > 0,
			StorageLimitMB:        storage,
			ConnectionsLimit:      conns,
			Deployments:           h.plans.DeploymentsAppsLimit(t.key),
			BackupRetentionDays:   h.plans.BackupRetentionDays(t.key),
			BackupRestoreEnabled:  h.plans.BackupRestoreEnabled(t.key),
			ManualBackupsPerDay:   h.plans.ManualBackupsPerDay(t.key),
			AnnualDiscountPercent: t.annualPct,
			UpgradeURL:            "https://instanode.dev/pricing/",
		})
	}

	return c.JSON(fiber.Map{
		"ok":     true,
		"tiers":  out,
		"docs":   "https://instanode.dev/llms-full.txt",
		"contact": "mailto:enterprise@instanode.dev",
	})
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
