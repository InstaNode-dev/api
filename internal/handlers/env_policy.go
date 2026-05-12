package handlers

// env_policy.go — Team-level per-env access policy management endpoints.
//
// Slice 6 of ENV-AWARE-DEPLOYMENTS-DESIGN. Two routes:
//
//   GET /api/v1/team/env-policy — any team member reads
//   PUT /api/v1/team/env-policy — owner only, replaces the policy
//
// The policy itself is consumed by the RequireEnvAccess middleware (see
// internal/middleware/env_policy.go). The shape and validation rules live
// in models.ValidateEnvPolicy — this handler is just the REST surface.

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// EnvPolicyHandler serves GET/PUT /api/v1/team/env-policy.
type EnvPolicyHandler struct {
	db *sql.DB
}

// NewEnvPolicyHandler constructs an EnvPolicyHandler.
func NewEnvPolicyHandler(db *sql.DB) *EnvPolicyHandler {
	return &EnvPolicyHandler{db: db}
}

// Get handles GET /api/v1/team/env-policy. Any authenticated team member may
// read the policy — the dashboard's settings page needs read access to show
// the current state, even for non-owners (so they can see why their action
// was denied).
func (h *EnvPolicyHandler) Get(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	policy, err := models.GetTeamEnvPolicy(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("env_policy.get.failed",
			"error", err, "team_id", teamID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "fetch_failed",
			"Failed to read env policy")
	}
	// Always return an object, never null — agents/dashboard expect a stable
	// shape. An empty policy serialises as `{}`.
	if policy == nil {
		policy = models.EnvPolicy{}
	}
	return c.JSON(fiber.Map{
		"ok":     true,
		"policy": policy,
	})
}

// Put handles PUT /api/v1/team/env-policy. Owner only.
//
// Body shape: the policy object itself (NOT wrapped in `{"policy": ...}`).
// Example: { "production": { "deploy": ["owner"] } }
//
// Validation: see models.ValidateEnvPolicy — env names, action names, role
// names, and total size are all bounded. Unknown action names are rejected
// so a typo can't silently disable the policy.
func (h *EnvPolicyHandler) Put(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}

	// Owner-only enforcement. We use models.GetUserRole rather than
	// middleware.RequireRole("owner") because the rejection body must carry
	// the canonical env-policy 403 shape (env_policy_denied) so dashboard
	// + agent error handling matches the per-action rejection.
	role, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil {
		slog.Error("env_policy.put.role_lookup_failed",
			"error", err, "team_id", teamID, "user_id", userID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "role_lookup_failed",
			"Failed to verify owner role")
	}
	if role != middleware.RoleOwner {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"ok":            false,
			"error":         "owner_required",
			"role":          role,
			"allowed_roles": []string{middleware.RoleOwner},
			"agent_action":  newAgentActionOwnerRequired(role),
		})
	}

	body := c.Body()
	if len(body) == 0 {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			`Body must be a JSON object of shape {"<env>":{"<action>":["<role>",...]}}`)
	}
	policy, vErr := models.ValidateEnvPolicy(body)
	if vErr != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_env_policy", vErr.Error())
	}
	if err := models.SetTeamEnvPolicy(c.Context(), h.db, teamID, policy); err != nil {
		var notFound *models.ErrTeamNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "Team not found")
		}
		slog.Error("env_policy.put.persist_failed",
			"error", err, "team_id", teamID,
			"request_id", middleware.GetRequestID(c))
		return respondError(c, fiber.StatusServiceUnavailable, "persist_failed",
			"Failed to persist env policy")
	}

	// Best-effort audit log — failure must not block the response. We
	// detach from the request context (which the Fiber ctx pool recycles
	// after Put returns) and use a fresh context.Background() so the
	// goroutine doesn't dereference a stale ctx pointer.
	go func(tid, uid uuid.UUID, actor string) {
		_ = models.InsertAuditEvent(context.Background(), h.db, models.AuditEvent{
			TeamID:  tid,
			UserID:  uuid.NullUUID{UUID: uid, Valid: true},
			Actor:   actor,
			Kind:    "env_policy.updated",
			Summary: "Team env-policy updated",
		})
	}(teamID, userID, role)

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"ok":     true,
		"policy": policy,
	})
}
