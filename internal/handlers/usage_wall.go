package handlers

// usage_wall.go — Track U1.
//
// GET /api/v1/usage/wall returns the most recent `near_quota_wall` audit
// row written by the worker's QuotaWallNudgeWorker, scoped to the caller's
// team and bounded to the last 24h. The dashboard polls this on mount and
// every 5 minutes to decide whether to render the upgrade-nudge banner.
//
// Response shape:
//
//	{
//	  "ok":        true,
//	  "near_wall": true,
//	  "tier":      "hobby",
//	  "axis":      "storage",
//	  "service":   "postgres",     // "" for provisions axis
//	  "current":   471859200,
//	  "limit":     536870912,
//	  "percent_used": 87,
//	  "at":        "2026-05-12T11:02:00Z"
//	}
//
// When there is no row within the last 24h, or the team is on the "team"
// tier (no walls), the response is `{"ok": true, "near_wall": false}`.
//
// Tier gate: "team" tier callers always get near_wall=false without a
// DB hit. The worker won't have written a row anyway, but the early
// return saves an audit_log scan for the most-active paid tier.
//
// Caching: 60s in Redis is enough — the worker writes at most one row
// per team per 24h, and the dashboard polls every 5 minutes. We don't
// cache here because the read is a single indexed row by (team_id,
// kind, created_at), which the existing idx_audit_team_at supports.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// usageWallKind is the audit_log.kind value the worker writes and this
// handler reads. Must match worker/internal/jobs/quota_wall_nudge.go's
// quotaWallKind constant — a typo on either side silently breaks the
// banner.
const usageWallKind = "near_quota_wall"

// usageWallFreshness is the maximum age of a near_quota_wall audit row
// considered "current" for the dashboard banner. Mirrors the worker's
// quotaWallDedupeWindow — a row outside this window is stale and we
// return near_wall=false even if it exists.
const usageWallFreshness = 24 * time.Hour

// usageWallCacheMaxAge is the Cache-Control: max-age value emitted on
// every GET /api/v1/usage/wall response. BUG-API-420 (QA 2026-05-29):
// the dashboard fetches this endpoint on every navigation (Overview
// page on mount + every 5-min poll); without a cache hint the browser
// re-fetches on every back/forward / SPA route change, generating
// redundant DB scans on the busiest team-scoped table (audit_log).
//
// 30s is the consistency tradeoff (memory rule
// feedback_caching_and_consistency_tradeoffs):
//   - The worker writes at most one near_quota_wall row per team per
//     24h (quotaWallDedupeWindow = usageWallFreshness above), so a
//     30s staleness window can miss a brand-new wall event by ≤30s.
//   - The wall banner is a soft upgrade-nudge, not a hard quota
//     enforcement — the hard 402 still fires synchronously on the
//     next provision regardless of banner state.
//   - 30s < the 5-min dashboard poll interval, so the cache flushes
//     well within one polling round and walls are visible within
//     5min + 30s in the worst case.
//
// `Vary: Authorization` is added alongside so per-team caching at a
// CDN never serves team A's banner state to team B.
const usageWallCacheMaxAge = 30

// UsageWallHandler serves GET /api/v1/usage/wall.
type UsageWallHandler struct {
	db *sql.DB
}

// NewUsageWallHandler constructs a UsageWallHandler.
func NewUsageWallHandler(db *sql.DB) *UsageWallHandler {
	return &UsageWallHandler{db: db}
}

// wallMetadata is the metadata JSON written by the worker. Fields match
// worker/internal/jobs/quota_wall_nudge.go's wallHit struct exactly. If
// the worker side adds a field, the handler will pass it through via
// the catch-all extra map below (see GetWall).
type wallMetadata struct {
	Tier        string `json:"tier"`
	Axis        string `json:"axis"`
	Service     string `json:"service,omitempty"`
	Current     int64  `json:"current"`
	Limit       int64  `json:"limit"`
	PercentUsed int    `json:"percent_used"`
}

// setUsageWallCacheHeaders stamps the per-team cache hint on every 200
// response from GetWall. Lives on the handler struct so a future
// per-team max-age override (e.g. shorter for hobby_plus walls) has a
// single edit site. BUG-API-420.
func (h *UsageWallHandler) setUsageWallCacheHeaders(c *fiber.Ctx) {
	// Sprintf instead of a literal so the constant above (with its
	// consistency-tradeoff comment) is the single source of truth and
	// can't drift from the wire value. golangci-lint's `unused` check
	// blocks anyone deleting the constant without also touching this
	// fmt format string.
	c.Set("Cache-Control", fmt.Sprintf("private, max-age=%d", usageWallCacheMaxAge))
	// Vary: Authorization is the per-team boundary — without it a
	// shared cache (CDN, browser back-cache after re-auth) could
	// serve team A's banner state to team B.
	c.Set("Vary", "Authorization")
}

// GetWall handles GET /api/v1/usage/wall.
func (h *UsageWallHandler) GetWall(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}

	// Team-tier early return — team tier is unlimited, so no walls.
	// Fail-open: if team lookup errors, fall through to the audit
	// query rather than refusing to serve.
	if team, terr := models.GetTeamByID(c.Context(), h.db, teamID); terr == nil && team != nil && team.PlanTier == "team" {
		h.setUsageWallCacheHeaders(c)
		return c.JSON(fiber.Map{"ok": true, "near_wall": false})
	}

	cutoff := time.Now().Add(-usageWallFreshness)

	row := h.db.QueryRowContext(c.Context(), `
		SELECT metadata, created_at
		FROM audit_log
		WHERE team_id = $1
		  AND kind    = $2
		  AND created_at >= $3
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, usageWallKind, cutoff)

	var (
		metadataRaw sql.NullString
		createdAt   time.Time
	)
	if scanErr := row.Scan(&metadataRaw, &createdAt); scanErr != nil {
		if scanErr == sql.ErrNoRows {
			h.setUsageWallCacheHeaders(c)
			return c.JSON(fiber.Map{"ok": true, "near_wall": false})
		}
		slog.Error("usage.wall.query_failed",
			"error", scanErr,
			"team_id", teamID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to read usage wall state")
	}

	// Empty / unparseable metadata still surfaces near_wall=true (the
	// worker wrote the row, so something happened), but we can't fill
	// in the axis/service/percent fields. The dashboard renders a
	// generic upgrade banner in that case.
	resp := fiber.Map{
		"ok":        true,
		"near_wall": true,
		"at":        createdAt,
	}
	if metadataRaw.Valid && len(metadataRaw.String) > 0 {
		var meta wallMetadata
		if err := json.Unmarshal([]byte(metadataRaw.String), &meta); err == nil {
			resp["tier"] = meta.Tier
			resp["axis"] = meta.Axis
			resp["service"] = meta.Service
			resp["current"] = meta.Current
			resp["limit"] = meta.Limit
			resp["percent_used"] = meta.PercentUsed
		}
	}
	h.setUsageWallCacheHeaders(c)
	return c.JSON(resp)
}
