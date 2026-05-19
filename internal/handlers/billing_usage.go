package handlers

import (
	"context"
	"database/sql"
	"log/slog"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/cache"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// BillingUsageHandler serves the cached billing-usage aggregate consumed by
// the dashboard's BillingPage. It replaces the client-side aggregation that
// previously summed storage_bytes per type in the browser — that path forced
// the dashboard to fetch the full resource list just to compute the Usage
// panel, and every concurrent tab triggered its own DB scan via /resources.
//
// Now the aggregation happens once per team per cache window (30s) and the
// answer is shared across every surface that needs it (BillingPage, the
// future MCP agent_usage_summary tool, etc.).
//
// Real-time paths (POST /db/new etc.) MUST NOT use this aggregate — they
// gate on a fresh DB read per §13.
type BillingUsageHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	plans *plans.Registry
}

// NewBillingUsageHandler builds a BillingUsageHandler. rdb may be nil in
// tests / configs where caching is disabled (the cache helper handles nil
// transparently).
func NewBillingUsageHandler(db *sql.DB, rdb *redis.Client, p *plans.Registry) *BillingUsageHandler {
	return &BillingUsageHandler{db: db, rdb: rdb, plans: p}
}

// billingUsageTTL is the cache freshness window for /api/v1/billing/usage.
// 30s matches the §13 freshness target and the Cache-Control max-age below.
// Tune as a single source of truth: change here, the response's
// `freshness_seconds` and the Cache-Control header both follow.
const billingUsageTTL = 30 * time.Second

// usageSummary is the cached payload — JSON-encoded into Redis. Field tags
// match the public response shape per §10.20.2 so the same struct serialises
// both ways (cache value + HTTP response body) and there's no second mapping
// step.
type usageSummary struct {
	OK               bool                   `json:"ok"`
	FreshnessSeconds int                    `json:"freshness_seconds"`
	AsOf             string                 `json:"as_of"`
	Usage            map[string]usageMetric `json:"usage"`
}

// usageMetric carries both `bytes` (storage services) and `count` (deploys,
// webhooks, vault, members). Only the relevant field renders per metric —
// the other stays at -1 to mean "not applicable to this kind". Limits stay
// at -1 to mean "unlimited" (matches plans.yaml convention).
type usageMetric struct {
	Bytes      int64 `json:"bytes,omitempty"`
	LimitBytes int64 `json:"limit_bytes,omitempty"`
	Count      int   `json:"count,omitempty"`
	Limit      int   `json:"limit,omitempty"`
}

// GetUsage handles GET /api/v1/billing/usage.
//
// Auth: session JWT (required by the /api/v1 RequireAuth middleware in the
// router). Team scope comes from the JWT claims — no team_id in the path.
//
// Cache: 30s in Redis under "billing:usage:<team_id>". Concurrent callers
// collapse via singleflight. Redis-down → fall through to fn (no caching
// for that request). HTTP response sets:
//
//	Cache-Control: private, max-age=30, stale-while-revalidate=60
//
// so browsers + intermediate proxies honour the same window without
// hammering the API.
//
// Response shape (per §10.20.2):
//
//	{
//	  "ok": true,
//	  "freshness_seconds": 30,
//	  "as_of": "2026-05-12T00:00:00Z",
//	  "usage": {
//	    "postgres":   { "bytes": ..., "limit_bytes": ... },
//	    "redis":      { "bytes": ..., "limit_bytes": ... },
//	    "mongodb":    { ... },
//	    "deployments": { "count": ..., "limit": ... },
//	    "webhooks":   { "count": ..., "limit": ... },
//	    "vault":      { "count": ..., "limit": ... },
//	    "members":    { "count": ..., "limit": ... }
//	  }
//	}
func (h *BillingUsageHandler) GetUsage(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	key := "billing:usage:" + teamID.String()

	summary, err := cache.GetOrSet(c.Context(), h.rdb, key, billingUsageTTL,
		func(ctx context.Context) (usageSummary, error) {
			return h.computeUsage(ctx, teamID)
		})
	if err != nil {
		slog.Error("billing.usage.compute_failed",
			"error", err, "team_id", teamID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, "usage_failed", "Failed to compute usage")
	}

	// Cache-Control matches the TTL so the browser respects the same
	// window. private = don't cache in shared proxies (per-team data).
	// stale-while-revalidate gives a 60s grace window where the browser
	// can serve the stale value while it kicks off a background refresh.
	c.Set("Cache-Control", "private, max-age="+strconv.Itoa(int(billingUsageTTL.Seconds()))+", stale-while-revalidate=60")
	return c.JSON(summary)
}

// computeUsage runs the DB aggregations for one team. Called from cache miss
// + every Redis-down request. The function is broken out so tests can hit
// it directly (counting DB queries) without going through the cache layer.
//
// Each aggregate is queried independently — a failure on `members` doesn't
// fail the storage rows. The first hard error wins (returned to caller); the
// rest are best-effort.
func (h *BillingUsageHandler) computeUsage(ctx context.Context, teamID uuid.UUID) (usageSummary, error) {
	tier, err := h.tierForTeam(ctx, teamID)
	if err != nil {
		return usageSummary{}, err
	}

	usage := map[string]usageMetric{}

	// Storage services (bytes + limit_bytes). MB limits from plans.yaml are
	// converted to bytes inline so the dashboard doesn't need a unit-aware
	// formatter.
	for _, svc := range []string{"postgres", "redis", "mongodb"} {
		bytes, sumErr := models.SumStorageBytesByTeamAndType(ctx, h.db, teamID, svc)
		if sumErr != nil {
			return usageSummary{}, sumErr
		}
		limitMB := h.plans.StorageLimitMB(tier, svc)
		usage[svc] = usageMetric{
			Bytes:      bytes,
			LimitBytes: mbToBytes(limitMB),
		}
	}

	// Counts: deployments / webhooks / vault / members. Each independent.
	deployCount, _ := h.countDeployments(ctx, teamID)
	usage["deployments"] = usageMetric{
		Count: deployCount,
		Limit: h.plans.DeploymentsAppsLimit(tier),
	}

	webhookCount, _ := models.CountActiveResourcesByTeamAndType(ctx, h.db, teamID, "webhook")
	usage["webhooks"] = usageMetric{
		Count: webhookCount,
		Limit: h.plans.StorageLimitMB(tier, "webhook"), // webhook_requests_stored, reused here as a count cap
	}

	vaultCount, _ := models.CountVaultKeysByTeam(ctx, h.db, teamID)
	usage["vault"] = usageMetric{
		Count: vaultCount,
		Limit: h.plans.VaultMaxEntries(tier),
	}

	memberCount, _ := models.CountTeamMembers(ctx, h.db, teamID)
	usage["members"] = usageMetric{
		Count: memberCount,
		Limit: h.plans.TeamMemberLimit(tier),
	}

	return usageSummary{
		OK:               true,
		FreshnessSeconds: int(billingUsageTTL.Seconds()),
		AsOf:             time.Now().UTC().Format(time.RFC3339Nano),
		Usage:            usage,
	}, nil
}

// tierForTeam resolves the team's current plan_tier. Falls back to
// "anonymous" if the team row is missing — defensive against a torn DB
// state, and the plans.Registry treats unknown tiers as anonymous anyway.
func (h *BillingUsageHandler) tierForTeam(ctx context.Context, teamID uuid.UUID) (string, error) {
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		return "anonymous", err
	}
	return team.PlanTier, nil
}

// countDeployments counts a team's user-visible deployments across all envs —
// the exact row set GET /api/v1/deployments returns.
//
// S5-F4 (bug hunt): this counter previously delegated to
// CountActiveDeploymentsByTeam, which counts only billable tier slots
// (building/deploying/healthy). That is the right filter for the
// POST /deploy/new tier gate but the WRONG one for the usage panel: the panel
// must mirror what the user sees in the dashboard's deployments list, and the
// list endpoint includes failed/stopped deployments. The two endpoints counted
// different row sets, so a team could see usage.deployments.count=1 against an
// empty /api/v1/deployments list.
//
// It now delegates to CountVisibleDeploymentsByTeam, which shares
// models.deploymentVisibleClause with GetDeploymentsByTeam — the list query —
// so the usage count and the list length can never drift again.
func (h *BillingUsageHandler) countDeployments(ctx context.Context, teamID uuid.UUID) (int, error) {
	return models.CountVisibleDeploymentsByTeam(ctx, h.db, teamID)
}

// mbToBytes converts a plans.yaml megabyte value to bytes. -1 (unlimited)
// stays -1 so the dashboard renders "∞".
func mbToBytes(mb int) int64 {
	if mb < 0 {
		return -1
	}
	return int64(mb) * 1024 * 1024
}
