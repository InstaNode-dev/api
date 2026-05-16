package handlers

// deploy_ttl.go — Wave FIX-J TTL-keeper endpoints.
//
// Lives alongside deploy.go but in its own file so the make-permanent /
// set-TTL flow stays cleanly separable from the deploy CRUD shape. The
// hot-path POST /deploy/new + DELETE /deploy/:id stay in deploy.go; the
// new opt-in-to-permanent surface is here.
//
// Routes:
//   POST /api/v1/deployments/:id/make-permanent — opt the deploy out of TTL
//   POST /api/v1/deployments/:id/ttl            — set a custom TTL
//
// Both endpoints share the same cross-tenant 404 posture as the rest of
// the deploy surface — a deploy you don't own returns 404, not 403, so
// the existence of arbitrary deploy IDs can't be probed.

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// MakePermanent handles POST /api/v1/deployments/:id/make-permanent.
//
// Opts a deploy out of the auto_24h TTL — sets expires_at = NULL and
// ttl_policy = 'permanent'. Idempotent: calling twice is a no-op.
//
// Anonymous tier is REJECTED with 402 + a claim-the-account agent_action:
// anonymous deploys are always-24h with no escape hatch other than claiming.
//
// Cross-tenant 404: deploys belonging to other teams return 404, never 403.
//
// Audit kind: deploy.made_permanent with source="make_permanent_endpoint".
func (h *DeployHandler) MakePermanent(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	// :id can be either the uuid or the app_id slug. Try uuid first,
	// fall through to app_id (matches the existing GET /deploy/:id
	// convention — see Get handler).
	rawID := c.Params("id")
	d, err := lookupDeployment(c, h.db, rawID)
	if err != nil {
		return err
	}
	if d.TeamID != team.ID {
		// Cross-tenant 404 — never 403 (avoids leaking the existence of
		// deploys belonging to other teams).
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	if team.PlanTier == "anonymous" {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"upgrade_required",
			"Anonymous deploys cannot be made permanent — they always expire in 24h. Claim the account to keep deploys.",
			AgentActionDeployMakePermanentAnonymous,
			"https://api.instanode.dev/start")
	}

	previousPolicy := d.TTLPolicy
	if err := models.MakeDeploymentPermanent(c.Context(), h.db, d.ID); err != nil {
		slog.Error("deploy.make_permanent.failed",
			"deploy_id", d.ID, "team_id", team.ID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed",
			"Failed to make deployment permanent")
	}

	// Refresh so the response shape matches the new state.
	updated, err := models.GetDeploymentByID(c.Context(), h.db, d.ID)
	if err != nil {
		slog.Error("deploy.make_permanent.refresh_failed", "deploy_id", d.ID, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Update succeeded but reload failed")
	}

	// audit_log emit. Only fires when the policy actually changed — calling
	// make-permanent on an already-permanent deploy stays idempotent and
	// doesn't generate a spurious row.
	if previousPolicy != models.DeployTTLPolicyPermanent {
		emitDeployAudit(h.db, models.AuditKindDeployMadePermanent, updated, map[string]any{
			"source":              "make_permanent_endpoint",
			"previous_ttl_policy": previousPolicy,
		})
	}

	slog.Info("deploy.make_permanent.ok",
		"deploy_id", d.ID, "team_id", team.ID, "previous_ttl_policy", previousPolicy)

	return c.JSON(fiber.Map{
		"ok":   true,
		"item": deploymentToMap(updated),
		"note": "Deployment kept permanently. To re-enable TTL, call POST https://api.instanode.dev/api/v1/deployments/" + d.ID.String() + "/ttl {\"hours\":24}.",
	})
}

// SetTTLRequest is the JSON body for POST /api/v1/deployments/:id/ttl.
type SetTTLRequest struct {
	Hours int `json:"hours"`
}

// SetTTL handles POST /api/v1/deployments/:id/ttl.
//
// Sets a custom TTL: expires_at = now() + hours, ttl_policy = 'custom'.
// hours must be in [1, 8760] (1 hour to 1 year). Also resets reminders_sent
// to 0 so a freshly-extended deploy gets the full 6-email warning cycle.
//
// Anonymous tier is REJECTED — same posture as MakePermanent.
//
// Audit kind: deploy.ttl_set.
func (h *DeployHandler) SetTTL(c *fiber.Ctx) error {
	team, err := h.requireTeam(c)
	if err != nil {
		return err
	}

	rawID := c.Params("id")
	d, err := lookupDeployment(c, h.db, rawID)
	if err != nil {
		return err
	}
	if d.TeamID != team.ID {
		return respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
	}

	if team.PlanTier == "anonymous" {
		return respondErrorWithAgentAction(c, fiber.StatusPaymentRequired,
			"upgrade_required",
			"Anonymous deploys have a fixed 24h TTL — custom TTL requires a claimed account.",
			AgentActionDeployMakePermanentAnonymous,
			"https://api.instanode.dev/start")
	}

	var body SetTTLRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	if body.Hours < 1 || body.Hours > 8760 {
		return respondErrorWithAgentAction(c, fiber.StatusBadRequest,
			"invalid_hours",
			fmt.Sprintf("hours must be between 1 and 8760 (got %d)", body.Hours),
			AgentActionDeployTTLHoursOutOfRange,
			"")
	}

	if err := models.SetDeploymentTTL(c.Context(), h.db, d.ID, body.Hours); err != nil {
		slog.Error("deploy.set_ttl.failed",
			"deploy_id", d.ID, "team_id", team.ID, "error", err,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed",
			"Failed to set TTL")
	}

	updated, err := models.GetDeploymentByID(c.Context(), h.db, d.ID)
	if err != nil {
		slog.Error("deploy.set_ttl.refresh_failed", "deploy_id", d.ID, "error", err)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Update succeeded but reload failed")
	}

	emitDeployAudit(h.db, models.AuditKindDeployTTLSet, updated, map[string]any{
		"hours":      body.Hours,
		"expires_at": updated.ExpiresAt.Time.UTC().Format(time.RFC3339),
	})

	slog.Info("deploy.set_ttl.ok",
		"deploy_id", d.ID, "team_id", team.ID, "hours", body.Hours)

	return c.JSON(fiber.Map{
		"ok":   true,
		"item": deploymentToMap(updated),
		"note": fmt.Sprintf("TTL set to %dh. Six reminder emails will fire over the final 12h. Call POST /api/v1/deployments/%s/make-permanent to disable TTL entirely.",
			body.Hours, d.ID.String()),
	})
}

// lookupDeployment resolves :id to a Deployment. Tries app_id (slug) first
// because that's the public-facing identifier returned in /deploy/new
// responses, then falls through to UUID for older clients that have the
// id field. Returns the appropriate respondError on failure.
func lookupDeployment(c *fiber.Ctx, db *sql.DB, rawID string) (*models.Deployment, error) {
	if rawID == "" {
		return nil, respondError(c, fiber.StatusBadRequest, "missing_id", "Deployment id is required")
	}
	// Try app_id first.
	d, err := models.GetDeploymentByAppID(c.Context(), db, rawID)
	if err == nil {
		return d, nil
	}
	var notFound *models.ErrDeploymentNotFound
	if errors.As(err, &notFound) {
		// Fall through to UUID lookup.
		uid, parseErr := uuid.Parse(rawID)
		if parseErr == nil {
			d, err = models.GetDeploymentByID(c.Context(), db, uid)
			if err == nil {
				return d, nil
			}
			if errors.As(err, &notFound) {
				return nil, respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
			}
		} else {
			return nil, respondError(c, fiber.StatusNotFound, "not_found", "Deployment not found")
		}
	}
	if err != nil {
		slog.Error("deploy.lookup.failed", "raw_id", rawID, "error", err)
		return nil, respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to fetch deployment")
	}
	return d, nil
}
