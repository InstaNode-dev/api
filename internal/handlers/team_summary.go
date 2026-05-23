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

// TeamSummaryHandler serves the cached team-level counts the dashboard
// sidebar (SidebarUpgradeCard, badge numbers) renders. It avoids the
// previous pattern where every <NavRow> page-load triggered its own
// /api/v1/resources scan to compute a single number.
//
// 5-minute cache window — the sidebar numbers don't need to be fresh on
// the millisecond; a resource provisioned in another tab will appear on
// the next refresh within 5 min. The §13 freshness matrix calls this
// eventual-consistent on purpose.
type TeamSummaryHandler struct {
	db    *sql.DB
	rdb   *redis.Client
	plans *plans.Registry
}

// NewTeamSummaryHandler builds a TeamSummaryHandler. rdb may be nil.
func NewTeamSummaryHandler(db *sql.DB, rdb *redis.Client, p *plans.Registry) *TeamSummaryHandler {
	return &TeamSummaryHandler{db: db, rdb: rdb, plans: p}
}

// teamSummaryTTL — 5 minutes is long enough that one signed-in user opening
// every dashboard page across a session triggers ~1 aggregate per surface,
// short enough that a provision/delete is visible quickly.
const teamSummaryTTL = 5 * time.Minute

// teamSummary is both the cached payload and the public response. Keeping
// the struct shared means a deploy-time JSON shape change naturally
// invalidates older cache entries (json.Unmarshal fails → cache helper
// treats as miss → next request rebuilds).
type teamSummary struct {
	OK               bool                 `json:"ok"`
	FreshnessSeconds int                  `json:"freshness_seconds"`
	AsOf             string               `json:"as_of"`
	Tier             string               `json:"tier"`
	Counts           teamSummaryCountsRes `json:"counts"`
}

// teamSummaryCountsRes carries the four "how many X do we have" counts the
// sidebar consumes. Each is a separate field rather than a generic map so
// the JSON shape is stable (and the dashboard's TypeScript types match
// exactly).
type teamSummaryCountsRes struct {
	Resources   resourceTypeCounts `json:"resources"`
	Deployments int                `json:"deployments"`
	Members     int                `json:"members"`
	VaultKeys   int                `json:"vault_keys"`
}

// resourceTypeCounts gives per-type breakdown of active resources. Total is
// the sum (saves the dashboard from re-adding). Per-type values let the
// sidebar's badge numbers ("Resources · 7") show without an extra query.
type resourceTypeCounts struct {
	Total    int `json:"total"`
	Postgres int `json:"postgres"`
	Redis    int `json:"redis"`
	Mongodb  int `json:"mongodb"`
	Webhook  int `json:"webhook"`
	Queue    int `json:"queue"`
	Storage  int `json:"storage"`
	Other    int `json:"other"`
}

// GetSummary handles GET /api/v1/team/summary.
//
// Auth: session JWT. Team scope comes from the JWT claims.
//
// Cache: 5 min in Redis under "team:summary:<team_id>". Concurrent callers
// collapse via singleflight. HTTP response sets:
//
//	Cache-Control: private, max-age=300
//
// (No stale-while-revalidate — at 5 min, the freshness window is already
// large enough that we don't need a soft-revalidate phase.)
func (h *TeamSummaryHandler) GetSummary(c *fiber.Ctx) error {
	teamIDStr := middleware.GetTeamID(c)
	teamID, err := uuid.Parse(teamIDStr)
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session token required")
	}

	key := "team:summary:" + teamID.String()

	summary, err := cache.GetOrSet(c.Context(), h.rdb, key, teamSummaryTTL,
		func(ctx context.Context) (teamSummary, error) {
			return h.computeSummary(ctx, teamID)
		})
	if err != nil {
		slog.Error("team.summary.compute_failed",
			"error", err, "team_id", teamID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusInternalServerError, "summary_failed", "Failed to compute team summary")
	}

	c.Set("Cache-Control", "private, max-age="+strconv.Itoa(int(teamSummaryTTL.Seconds())))
	return c.JSON(summary)
}

// computeSummary runs the DB queries for one team. Each is wrapped to be
// best-effort except the first (which determines the tier — a hard
// requirement). Broken out so tests can count DB calls directly.
func (h *TeamSummaryHandler) computeSummary(ctx context.Context, teamID uuid.UUID) (teamSummary, error) {
	team, err := models.GetTeamByID(ctx, h.db, teamID)
	if err != nil {
		return teamSummary{}, err
	}

	counts := teamSummaryCountsRes{}

	if rt, rterr := h.countResourcesByType(ctx, teamID); rterr == nil {
		counts.Resources = rt
	} else {
		slog.Warn("team.summary.resource_count_failed", "error", rterr, "team_id", teamID)
	}

	if n, derr := h.countDeployments(ctx, teamID); derr == nil {
		counts.Deployments = n
	} else {
		slog.Warn("team.summary.deploy_count_failed", "error", derr, "team_id", teamID)
	}

	if n, merr := models.CountTeamMembers(ctx, h.db, teamID); merr == nil {
		counts.Members = n
	} else {
		slog.Warn("team.summary.member_count_failed", "error", merr, "team_id", teamID)
	}

	if n, verr := models.CountVaultKeysByTeam(ctx, h.db, teamID); verr == nil {
		counts.VaultKeys = n
	} else {
		slog.Warn("team.summary.vault_count_failed", "error", verr, "team_id", teamID)
	}

	return teamSummary{
		OK:               true,
		FreshnessSeconds: int(teamSummaryTTL.Seconds()),
		AsOf:             time.Now().UTC().Format(time.RFC3339Nano),
		Tier:             team.PlanTier,
		Counts:           counts,
	}, nil
}

// countResourcesByType runs one GROUP BY resource_type query and bins the
// rows into the resourceTypeCounts struct. One query for the whole breakdown
// — cheaper than six separate COUNTs.
func (h *TeamSummaryHandler) countResourcesByType(ctx context.Context, teamID uuid.UUID) (resourceTypeCounts, error) {
	out := resourceTypeCounts{}
	rows, err := h.db.QueryContext(ctx, `
		SELECT resource_type, COUNT(*)
		FROM resources
		WHERE team_id = $1 AND status = 'active'
		GROUP BY resource_type
	`, teamID)
	if err != nil {
		return out, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var t string
		var n int
		if scanErr := rows.Scan(&t, &n); scanErr != nil {
			return out, scanErr
		}
		out.Total += n
		switch t {
		case "postgres":
			out.Postgres = n
		case "redis":
			out.Redis = n
		case "mongodb":
			out.Mongodb = n
		case "webhook":
			out.Webhook = n
		case "queue":
			out.Queue = n
		case "storage":
			out.Storage = n
		default:
			// Unknown resource_type — most likely a new service shipped
			// since this code was written. Fold it into `other` so the
			// total stays accurate even when the breakdown doesn't have
			// a typed bucket yet.
			out.Other += n
		}
	}
	return out, rows.Err()
}

// countDeployments mirrors BillingUsageHandler.countDeployments — same
// "exclude deleted/stopped" rule. Duplicated rather than factored out
// because the two handlers live in different files and the duplication is
// trivial; consolidating would mean a small models.CountDeployments
// helper which is one PR's worth of churn for negligible value here.
func (h *TeamSummaryHandler) countDeployments(ctx context.Context, teamID uuid.UUID) (int, error) {
	var n int
	err := h.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM deployments
		WHERE team_id = $1
		  AND status NOT IN ('deleted', 'stopped')
	`, teamID).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}
