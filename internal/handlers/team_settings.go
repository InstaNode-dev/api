package handlers

// team_settings.go — Wave FIX-J team preferences endpoints.
//
// GET  /api/v1/team/settings — read the team's preferences
// PATCH /api/v1/team/settings — owner/admin only — mutate preferences
//
// Today's only setting is default_deployment_ttl_policy (migration 045).
// Future settings (default region, default env policy, etc.) land in this
// same handler — each new key gets a switch arm in Update and a copyMeta
// entry in the audit emit.
//
// Distinct from TeamSelfHandler (which owns team.name + the public summary).
// Settings are a separate noun because they evolve independently from the
// team's identity fields and need a tighter RBAC posture — only owner/admin
// can flip a default that affects every future provision call.

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
	"instant.dev/internal/safego"
)

// TeamSettingsHandler — GET / PATCH /api/v1/team/settings.
type TeamSettingsHandler struct {
	db *sql.DB
}

// NewTeamSettingsHandler constructs the handler.
func NewTeamSettingsHandler(db *sql.DB) *TeamSettingsHandler {
	return &TeamSettingsHandler{db: db}
}

// teamSettingsResponse is the public shape returned from GET / PATCH.
type teamSettingsResponse struct {
	TeamID                     string `json:"team_id"`
	DefaultDeploymentTTLPolicy string `json:"default_deployment_ttl_policy"`
	// DefaultDeploymentTTLHours is emitted as a convenience so dashboards
	// can render "24h" / "permanent" without having to know the mapping.
	// Today this is always 24 for auto_24h and 0 (sentinel for "no TTL")
	// for permanent — but we surface it as a separate field so a future
	// per-team-configurable hours value doesn't break the contract.
	DefaultDeploymentTTLHours int `json:"default_deployment_ttl_hours"`
}

func toTeamSettingsResponse(t *models.Team) teamSettingsResponse {
	policy := t.DefaultDeploymentTTLPolicy
	if policy == "" {
		policy = models.DeployTTLPolicyAuto24h
	}
	hours := 24
	if policy == models.DeployTTLPolicyPermanent {
		hours = 0
	}
	return teamSettingsResponse{
		TeamID:                     t.ID.String(),
		DefaultDeploymentTTLPolicy: policy,
		DefaultDeploymentTTLHours:  hours,
	}
}

// Get — GET /api/v1/team/settings. Returns the team's preferences.
func (h *TeamSettingsHandler) Get(c *fiber.Ctx) error {
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
		slog.Error("team_settings.get.failed",
			"error", err, "team_id", teamID, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to load settings")
	}
	return c.JSON(fiber.Map{"ok": true, "settings": toTeamSettingsResponse(t)})
}

// updateTeamSettingsRequest is the JSON body for PATCH /api/v1/team/settings.
// Pointer types so we can distinguish "unset" (don't touch) from "empty"
// (caller asked to clear). Today only DefaultDeploymentTTLPolicy is settable.
type updateTeamSettingsRequest struct {
	DefaultDeploymentTTLPolicy *string `json:"default_deployment_ttl_policy"`
}

// Update — PATCH /api/v1/team/settings. Owner or admin only (RBAC enforced
// at the route layer via middleware.RequireRole("admin")).
//
// Today the only field is default_deployment_ttl_policy ∈ {auto_24h, permanent}.
// Adding a new setting = (1) a pointer field on updateTeamSettingsRequest,
// (2) a switch arm here that validates + persists + emits an audit row,
// (3) an entry in toTeamSettingsResponse.
//
// audit_log: emits team.settings_changed per field changed. The audit row's
// metadata carries {field, old_value, new_value, changed_by_user_id} so the
// dashboard's Recent Activity feed renders one line per mutation.
func (h *TeamSettingsHandler) Update(c *fiber.Ctx) error {
	teamID, err := parseTeamID(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}

	var body updateTeamSettingsRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}

	t, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "not_found", "Team not found")
		}
		slog.Error("team_settings.update.fetch_failed",
			"error", err, "team_id", teamID, "request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Failed to load team")
	}

	// Track which fields changed so we emit one audit row per mutation.
	type fieldChange struct {
		field    string
		oldValue string
		newValue string
	}
	var changes []fieldChange

	if body.DefaultDeploymentTTLPolicy != nil {
		policy := strings.TrimSpace(strings.ToLower(*body.DefaultDeploymentTTLPolicy))
		switch policy {
		case models.DeployTTLPolicyAuto24h, models.DeployTTLPolicyPermanent:
			// ok
		default:
			return respondErrorWithAgentAction(c, fiber.StatusBadRequest,
				"invalid_ttl_policy",
				"default_deployment_ttl_policy must be 'auto_24h' or 'permanent'",
				AgentActionTeamSettingsInvalidTTLPolicy, "")
		}
		if policy != t.DefaultDeploymentTTLPolicy {
			if err := models.UpdateTeamDefaultDeploymentTTLPolicy(c.Context(), h.db, teamID, policy); err != nil {
				slog.Error("team_settings.update.failed",
					"error", err, "team_id", teamID,
					"field", "default_deployment_ttl_policy",
					"request_id", middleware.GetRequestID(c))
				return respondError(c, fiber.StatusServiceUnavailable, "update_failed", "Failed to update setting")
			}
			changes = append(changes, fieldChange{
				field:    "default_deployment_ttl_policy",
				oldValue: t.DefaultDeploymentTTLPolicy,
				newValue: policy,
			})
		}
	}

	// Reload after mutations so the response reflects current state.
	updated, err := models.GetTeamByID(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("team_settings.update.reload_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed", "Update succeeded but reload failed")
	}

	// Audit emit — best-effort, fire-and-forget per existing convention
	// (see emitTeamUpdatedAudit in team_self.go).
	if len(changes) > 0 {
		userID := middleware.GetUserID(c)
		for _, ch := range changes {
			emitTeamSettingsChangedAudit(h.db, teamID, userID, ch.field, ch.oldValue, ch.newValue)
		}
	}

	return c.JSON(fiber.Map{"ok": true, "settings": toTeamSettingsResponse(updated)})
}

// emitTeamSettingsChangedAudit writes one row to audit_log for a single
// settings field change. Best-effort: errors are logged but never bubble
// up to the request handler. Mirrors emitTeamUpdatedAudit pattern.
func emitTeamSettingsChangedAudit(db *sql.DB, teamID uuid.UUID, userID, field, oldValue, newValue string) {
	meta, _ := json.Marshal(map[string]any{
		"field":              field,
		"old_value":          oldValue,
		"new_value":          newValue,
		"changed_by_user_id": userID,
	})
	safego.Go("team_settings.bg", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ev := models.AuditEvent{
			Kind:     models.AuditKindTeamSettingsChanged,
			TeamID:   teamID,
			Actor:    "user",
			Metadata: meta,
		}
		if err := models.InsertAuditEvent(ctx, db, ev); err != nil {
			slog.Warn("audit.team_settings_changed.insert_failed",
				"error", err, "team_id", teamID, "field", field)
		}
	})
}
