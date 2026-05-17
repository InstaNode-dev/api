package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/safego"
)

// TeamSelfHandler — GET / PATCH /api/v1/team.
//
// The dashboard's `getTeam()` previously derived the team object from
// /auth/me because the dedicated endpoint did not exist; `updateTeam()` was
// a no-op that returned the input unchanged. That made "Rename team" a
// visual lie. This handler wires both for real.
//
// Distinct from TeamsHandler (RBAC invitations) and TeamSummaryHandler
// (cached counts panel). Owns only the team-self resource: name + the
// public-safe subset of the row.
type TeamSelfHandler struct {
	db    *sql.DB
	plans *plans.Registry
}

func NewTeamSelfHandler(db *sql.DB, p *plans.Registry) *TeamSelfHandler {
	return &TeamSelfHandler{db: db, plans: p}
}

// teamSelfResponse is the public shape returned from GET / PATCH.
type teamSelfResponse struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	PlanTier              string `json:"plan_tier"`
	HasActiveSubscription bool   `json:"has_active_subscription"`
	CreatedAt             string `json:"created_at"`
}

func toTeamSelfResponse(t *models.Team) teamSelfResponse {
	name := ""
	if t.Name.Valid {
		name = t.Name.String
	}
	return teamSelfResponse{
		ID:                    t.ID.String(),
		Name:                  name,
		PlanTier:              t.PlanTier,
		HasActiveSubscription: t.RazorpaySubscriptionID.Valid,
		CreatedAt:             t.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// Get — GET /api/v1/team. Returns the caller's team row.
func (h *TeamSelfHandler) Get(c *fiber.Ctx) error {
	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	t, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		slog.Error("team.get.failed", "error", err, "team_id", teamID, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to load team")
	}
	return c.JSON(fiber.Map{"ok": true, "team": toTeamSelfResponse(t)})
}

type updateTeamRequest struct {
	Name string `json:"name"`
}

// Update — PATCH /api/v1/team. Owner-only. Updates the team's display name.
// Other fields (plan_tier, subscription) are NOT mutable here — they flow
// through Razorpay webhooks and admin-only paths.
func (h *TeamSelfHandler) Update(c *fiber.Ctx) error {
	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	// Read-only sessions (admin impersonation) are blocked by RequireWritable
	// middleware wired at the route layer — no inline check needed here.

	var body updateTeamRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_name", "name is required")
	}
	if len(name) > 200 {
		return respondError(c, fiber.StatusBadRequest, "name_too_long", "name must be 200 characters or fewer")
	}

	if err := updateTeamName(c.Context(), h.db, teamID, name); err != nil {
		slog.Error("team.update.failed", "error", err, "team_id", teamID, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "update_failed", "Failed to update team")
	}

	t, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("team.update.reload_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Update succeeded but reload failed")
	}

	emitTeamUpdatedAudit(c, h.db, teamID, name)

	return c.JSON(fiber.Map{"ok": true, "team": toTeamSelfResponse(t)})
}

func updateTeamName(ctx context.Context, db *sql.DB, teamID uuid.UUID, name string) error {
	_, err := db.ExecContext(ctx, `UPDATE teams SET name = $1 WHERE id = $2`, name, teamID)
	return err
}

func emitTeamUpdatedAudit(c *fiber.Ctx, db *sql.DB, teamID uuid.UUID, newName string) {
	meta, _ := json.Marshal(map[string]any{"field": "name", "new_value": newName})
	safego.Go("team_self.bg", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := models.InsertAuditEvent(ctx, db, models.AuditEvent{
			Kind:     models.AuditKindTeamUpdated,
			TeamID:   teamID,
			Actor:    "user",
			Metadata: meta,
		}); err != nil {
			slog.Warn("audit.team_updated.insert_failed", "error", err, "team_id", teamID)
		}
	})
}
