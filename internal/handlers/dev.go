package handlers

// dev.go — internal dev-only endpoints (registered only when ENVIRONMENT=development).
// These bypass Razorpay and directly mutate DB state for manual testing.
// Never register these routes in production — router.go gates them on cfg.Environment.

import (
	"database/sql"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/models"
)

// setTierRequest is the body for POST /internal/set-tier.
type setTierRequest struct {
	TeamID string `json:"team_id"`
	Tier   string `json:"tier"` // pro | team | growth
}

// NewSetTierHandler returns a handler for POST /internal/set-tier.
// Only upgrades are allowed (pro, team). Downgrade is intentionally blocked —
// use the real Razorpay cancellation flow for that path.
func NewSetTierHandler(db *sql.DB, aesKey string) fiber.Handler {
	// Only upgrade tiers are allowed. hobby is not accepted — downgrade is Razorpay's job.
	upgradeTiers := map[string]bool{"pro": true, "team": true, "growth": true}

	return func(c *fiber.Ctx) error {
		var req setTierRequest
		if err := c.BodyParser(&req); err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_body", "JSON body required")
		}
		if req.TeamID == "" {
			return respondError(c, fiber.StatusBadRequest, "missing_team_id", "team_id is required")
		}
		if !upgradeTiers[req.Tier] {
			return respondError(c, fiber.StatusBadRequest, "invalid_tier", "tier must be pro, team, or growth (downgrade not allowed here)")
		}

		teamID, err := uuid.Parse(req.TeamID)
		if err != nil {
			return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a valid UUID")
		}

		// Atomically upgrade the team tier + resources + deployments + stacks.
		// Mirrors the production Razorpay webhook path exactly.
		if err := models.UpgradeTeamAllTiers(c.Context(), db, teamID, req.Tier); err != nil {
			slog.Error("dev.set_tier.upgrade_all_tiers_failed", "error", err, "team_id", req.TeamID)
			return respondError(c, fiber.StatusServiceUnavailable, "upgrade_failed", "Failed to upgrade team tier")
		}

		slog.Info("dev.set_tier.done", "team_id", req.TeamID, "tier", req.Tier)

		return c.JSON(fiber.Map{
			"ok":      true,
			"team_id": req.TeamID,
			"tier":    req.Tier,
		})
	}
}
