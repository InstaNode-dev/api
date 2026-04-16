package handlers

// dev.go — internal dev-only endpoints (registered only when ENVIRONMENT=development).
// These bypass Razorpay and directly mutate DB state for manual testing.
// Never register these routes in production — router.go gates them on cfg.Environment.

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/crypto"
	"instant.dev/internal/migratorclient"
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
func NewSetTierHandler(db *sql.DB, aesKey string, migClient *migratorclient.Client) fiber.Handler {
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

		if err := models.UpdatePlanTier(c.Context(), db, teamID, req.Tier); err != nil {
			slog.Error("dev.set_tier.update_plan_failed", "error", err, "team_id", req.TeamID)
			return respondError(c, fiber.StatusServiceUnavailable, "update_failed", "Failed to update plan tier")
		}

		// Elevate all existing permanent resources to the new tier immediately.
		if err := models.ElevateResourceTiersByTeam(c.Context(), db, teamID, req.Tier); err != nil {
			slog.Warn("dev.set_tier.elevate_failed", "error", err, "team_id", req.TeamID)
		}

		// Trigger background data migration for all existing shared-infra resources.
		if migClient != nil && aesKey != "" {
			go triggerSetTierMigrations(db, aesKey, migClient, teamID, req.Tier, req.TeamID)
		}

		slog.Info("dev.set_tier.done", "team_id", req.TeamID, "tier", req.Tier)

		return c.JSON(fiber.Map{
			"ok":      true,
			"team_id": req.TeamID,
			"tier":    req.Tier,
		})
	}
}

// triggerSetTierMigrations runs in a goroutine and fires migrator jobs for all
// active permanent postgres/redis/mongodb resources that still live on shared infra.
func triggerSetTierMigrations(db *sql.DB, aesKeyHex string, migClient *migratorclient.Client, teamID uuid.UUID, targetTier, logTag string) {
	aesKey, err := crypto.ParseAESKey(aesKeyHex)
	if err != nil {
		slog.Error("dev.set_tier.migrations.aes_key_failed", "error", err, "team_id", logTag)
		return
	}

	resources, err := models.ListResourcesByTeam(context.Background(), db, teamID)
	if err != nil {
		slog.Error("dev.set_tier.migrations.list_failed", "error", err, "team_id", logTag)
		return
	}

	migratable := map[string]bool{"postgres": true, "redis": true, "mongodb": true}
	triggered := 0

	for _, r := range resources {
		if !migratable[r.ResourceType] || r.Status != "active" || r.ExpiresAt.Valid {
			continue
		}
		if r.MigrationStatus.Valid {
			switch r.MigrationStatus.String {
			case "complete", "running", "verifying":
				continue
			}
		}
		if !r.ConnectionURL.Valid || r.ConnectionURL.String == "" {
			continue
		}

		plainURL, decErr := crypto.Decrypt(aesKey, r.ConnectionURL.String)
		if decErr != nil {
			plainURL = r.ConnectionURL.String
		}
		if !strings.Contains(plainURL, ".svc.cluster.local") {
			continue // already on isolated (non-shared) infra
		}

		if err := migClient.Trigger(context.Background(), migratorclient.MigrationRequest{
			ResourceID:   r.ID.String(),
			ResourceType: r.ResourceType,
			Token:        r.Token.String(),
			SourceTier:   r.Tier,
			TargetTier:   targetTier,
			SourceURL:    plainURL,
			RequestID:    logTag,
		}); err != nil {
			slog.Warn("dev.set_tier.migrations.trigger_failed",
				"error", err, "resource_id", r.ID, "resource_type", r.ResourceType)
			continue
		}

		slog.Info("dev.set_tier.migrations.triggered",
			"resource_id", r.ID, "resource_type", r.ResourceType,
			"source_tier", r.Tier, "target_tier", targetTier)
		triggered++
	}

	slog.Info("dev.set_tier.migrations.done", "triggered", triggered, "team_id", logTag, "target_tier", targetTier)
}
