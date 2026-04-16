package handlers

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
)

// TeamMembersHandler serves REST team membership endpoints (mirrors dashboard gRPC behaviour).
type TeamMembersHandler struct {
	db     *sql.DB
	cfg    *config.Config
	plans  *plans.Registry
	mail   *email.Client
}

// NewTeamMembersHandler constructs a TeamMembersHandler.
func NewTeamMembersHandler(db *sql.DB, cfg *config.Config, reg *plans.Registry, mail *email.Client) *TeamMembersHandler {
	return &TeamMembersHandler{db: db, cfg: cfg, plans: reg, mail: mail}
}

func (h *TeamMembersHandler) teamPlanTier(c *fiber.Ctx, teamID uuid.UUID) (string, error) {
	var tier string
	err := h.db.QueryRowContext(c.Context(), `SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&tier)
	return tier, err
}

func (h *TeamMembersHandler) requireOwner(c *fiber.Ctx, teamID, userID uuid.UUID) bool {
	role, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil {
		slog.Error("team_members.role_lookup", "error", err)
		return false
	}
	return role == "owner"
}

// ListMembers handles GET /api/v1/team/members
func (h *TeamMembersHandler) ListMembers(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	role, err := models.GetUserRole(c.Context(), h.db, teamID, userID)
	if err != nil || (role != "owner" && role != "member") {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Not a member of this team")
	}
	members, err := models.ListTeamMembers(c.Context(), h.db, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "list_failed", "Failed to list members")
	}
	tier, err := h.teamPlanTier(c, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)
	items := make([]fiber.Map, 0, len(members))
	for _, m := range members {
		items = append(items, fiber.Map{
			"id":         m.ID.String(),
			"email":      m.Email,
			"role":       m.Role,
			"created_at": m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(fiber.Map{"ok": true, "members": items, "member_limit": limit})
}

type inviteBody struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// InviteMember handles POST /api/v1/team/members/invite
func (h *TeamMembersHandler) InviteMember(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, userID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	var body inviteBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	email := strings.TrimSpace(body.Email)
	if email == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email is required")
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if role == "" {
		role = "member"
	}
	tier, err := h.teamPlanTier(c, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)
	inv, err := models.InviteMember(c.Context(), h.db, teamID, email, role, userID, limit)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	teamRow, _ := models.GetTeamByID(c.Context(), h.db, teamID)
	teamName := ""
	if teamRow != nil && teamRow.Name.Valid {
		teamName = teamRow.Name.String
	}
	if h.mail != nil {
		base := strings.TrimRight(h.cfg.DashboardBaseURL, "/")
		acceptURL := base + "/settings?section=team&invite=" + inv.ID.String()
		if mailErr := h.mail.SendTeamInvite(c.Context(), inv.Email, teamName, acceptURL); mailErr != nil {
			slog.Warn("team_members.invite_email_failed", "error", mailErr)
		}
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok": true,
		"invitation": fiber.Map{
			"id":         inv.ID.String(),
			"email":      inv.Email,
			"role":       inv.Role,
			"status":     inv.Status,
			"invited_by": inv.InvitedBy.String(),
			"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// RemoveMember handles DELETE /api/v1/team/members/:user_id
func (h *TeamMembersHandler) RemoveMember(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	actorID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, actorID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	targetID, err := uuid.Parse(c.Params("user_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_user_id", "Invalid user id")
	}
	if err := models.RemoveMember(c.Context(), h.db, teamID, targetID); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// LeaveTeam handles POST /api/v1/team/members/leave
func (h *TeamMembersHandler) LeaveTeam(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if err := models.LeaveTeam(c.Context(), h.db, teamID, userID); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// ListInvitations handles GET /api/v1/team/invitations
func (h *TeamMembersHandler) ListInvitations(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, userID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	invs, err := models.ListInvitations(c.Context(), h.db, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "list_failed", "Failed to list invitations")
	}
	items := make([]fiber.Map, 0, len(invs))
	for _, inv := range invs {
		items = append(items, fiber.Map{
			"id":         inv.ID.String(),
			"email":      inv.Email,
			"role":       inv.Role,
			"status":     inv.Status,
			"invited_by": inv.InvitedBy.String(),
			"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
			"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return c.JSON(fiber.Map{"ok": true, "invitations": items})
}

// RevokeInvitation handles DELETE /api/v1/team/invitations/:id
func (h *TeamMembersHandler) RevokeInvitation(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if !h.requireOwner(c, teamID, userID) {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Owner only")
	}
	invID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Invalid invitation id")
	}
	inv, err := models.GetInvitationByID(c.Context(), h.db, invID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	if inv.TeamID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Invitation does not belong to this team")
	}
	if err := models.RevokeInvitation(c.Context(), h.db, invID); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// AcceptInvitation handles POST /api/v1/team/invitations/:id/accept
func (h *TeamMembersHandler) AcceptInvitation(c *fiber.Ctx) error {
	userID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	invID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Invalid invitation id")
	}
	inv, err := models.GetInvitationByID(c.Context(), h.db, invID)
	if err != nil {
		return teamMembersModelError(c, err)
	}
	tier, terr := h.teamPlanTier(c, inv.TeamID)
	if terr != nil {
		return respondError(c, fiber.StatusInternalServerError, "tier_failed", "Failed to read team plan")
	}
	limit := h.plans.TeamMemberLimit(tier)
	if err := models.AcceptInvitation(c.Context(), h.db, invID, userID, limit); err != nil {
		return teamMembersModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

func teamMembersModelError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, models.ErrNotTeamOwner):
		return respondError(c, fiber.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, models.ErrCannotRemoveOwner), errors.Is(err, models.ErrOwnerCannotLeave):
		return respondError(c, fiber.StatusConflict, "failed_precondition", err.Error())
	case errors.Is(err, models.ErrInvitationNotFound):
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, models.ErrInvitationExpired), errors.Is(err, models.ErrInvitationNotPending):
		return respondError(c, fiber.StatusConflict, "invitation_invalid", err.Error())
	case errors.Is(err, models.ErrEmailMismatchInvite):
		return respondError(c, fiber.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, models.ErrMemberLimitReached):
		return respondError(c, fiber.StatusConflict, "member_limit", err.Error())
	case errors.Is(err, models.ErrAlreadyTeamMember), errors.Is(err, models.ErrDuplicatePendingInvite):
		return respondError(c, fiber.StatusConflict, "duplicate", err.Error())
	case errors.Is(err, models.ErrInvalidInviteRole):
		return respondError(c, fiber.StatusBadRequest, "invalid_role", err.Error())
	default:
		var notFound *models.ErrUserNotFound
		if errors.As(err, &notFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", notFound.Error())
		}
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Request failed")
	}
}
