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
)

// TeamsHandler serves the RBAC-aware team endpoints:
//
//	POST   /api/v1/teams/:team_id/invitations
//	GET    /api/v1/teams/:team_id/invitations
//	DELETE /api/v1/teams/:team_id/invitations/:id
//	POST   /api/v1/invitations/:token/accept       (no auth — token IS the auth)
//
// Distinct from TeamMembersHandler (legacy /api/v1/team/members/* routes that
// use the simpler owner/member invite flow). The two coexist intentionally:
// this handler implements the new admin/developer/viewer RBAC tiers + token
// acceptance.
type TeamsHandler struct {
	db   *sql.DB
	cfg  *config.Config
	mail *email.Client
}

// NewTeamsHandler constructs a TeamsHandler.
func NewTeamsHandler(db *sql.DB, cfg *config.Config, mail *email.Client) *TeamsHandler {
	return &TeamsHandler{db: db, cfg: cfg, mail: mail}
}

// inviteRequest is the JSON body for POST /api/v1/teams/:team_id/invitations.
type inviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// CreateInvitation handles POST /api/v1/teams/:team_id/invitations.
// Owner / admin only (callers gate via RequireRole("admin")).
//
// Body: { "email": "user@example.com", "role": "developer" }
// 201:  { "ok": true, "invitation": { id, email, role, token, expires_at, ... } }
func (h *TeamsHandler) CreateInvitation(c *fiber.Ctx) error {
	teamID, err := h.requireTeamMatch(c)
	if err != nil {
		return err
	}
	actorID, err := uuid.Parse(middleware.GetUserID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}

	var body inviteRequest
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "Invalid JSON")
	}
	emailAddr := strings.TrimSpace(strings.ToLower(body.Email))
	if emailAddr == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_email", "email is required")
	}
	role := strings.TrimSpace(strings.ToLower(body.Role))
	if !models.IsValidInviteRole(role) {
		return respondError(c, fiber.StatusBadRequest, "invalid_role",
			"role must be one of: admin, developer, viewer")
	}

	inv, err := models.CreateRBACInvitation(c.Context(), h.db, teamID, emailAddr, role, actorID)
	if err != nil {
		return teamsModelError(c, err)
	}

	// Best-effort email — never fail the request if delivery fails.
	if h.mail != nil {
		base := strings.TrimRight(h.cfg.DashboardBaseURL, "/")
		acceptURL := base + "/invitations/" + inv.Token + "/accept"
		teamName := ""
		if t, terr := models.GetTeamByID(c.Context(), h.db, teamID); terr == nil && t.Name.Valid {
			teamName = t.Name.String
		}
		if mailErr := h.mail.SendTeamInvite(c.Context(), inv.Email, teamName, acceptURL); mailErr != nil {
			slog.Warn("teams.invite_email_failed", "error", mailErr, "invitation_id", inv.ID)
		}
	} else {
		slog.Info("teams.invite_email_stub", "to", inv.Email, "team_id", teamID, "token_present", true)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":         true,
		"invitation": serializeInvitation(inv),
	})
}

// ListInvitations handles GET /api/v1/teams/:team_id/invitations.
// Owner / admin only. Returns pending (not accepted) invites.
func (h *TeamsHandler) ListInvitations(c *fiber.Ctx) error {
	teamID, err := h.requireTeamMatch(c)
	if err != nil {
		return err
	}
	invs, err := models.ListRBACInvitations(c.Context(), h.db, teamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "list_failed", "Failed to list invitations")
	}
	items := make([]fiber.Map, 0, len(invs))
	for i := range invs {
		items = append(items, serializeInvitation(&invs[i]))
	}
	return c.JSON(fiber.Map{"ok": true, "invitations": items})
}

// RevokeInvitation handles DELETE /api/v1/teams/:team_id/invitations/:id.
// Owner / admin only. Marks the invitation revoked; returns 404 if missing,
// 410 Gone if already accepted, 403 if it belongs to another team.
func (h *TeamsHandler) RevokeInvitation(c *fiber.Ctx) error {
	teamID, err := h.requireTeamMatch(c)
	if err != nil {
		return err
	}
	invID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Invalid invitation id")
	}

	inv, err := models.GetRBACInvitationByID(c.Context(), h.db, invID)
	if err != nil {
		return teamsModelError(c, err)
	}
	if inv.TeamID != teamID {
		return respondError(c, fiber.StatusForbidden, "forbidden", "Invitation does not belong to this team")
	}
	if inv.AcceptedAt.Valid {
		return respondError(c, fiber.StatusGone, "already_accepted", "Invitation has already been accepted")
	}
	if err := models.RevokeRBACInvitation(c.Context(), h.db, invID); err != nil {
		return teamsModelError(c, err)
	}
	return c.JSON(fiber.Map{"ok": true})
}

// AcceptInvitation handles POST /api/v1/invitations/:token/accept.
//
// No auth required — the token IS the auth. On success, the invitee's user row
// is created or updated to belong to the inviting team with the invited role,
// and a fresh session JWT is returned so the client can immediately call other
// authenticated endpoints.
//
// Status codes:
//
//	200 — accepted; body includes session_token + user/team info
//	404 — token unknown
//	410 — token already used or expired (single-use guarantee)
func (h *TeamsHandler) AcceptInvitation(c *fiber.Ctx) error {
	token := c.Params("token")
	if len(token) < 16 {
		return respondError(c, fiber.StatusBadRequest, "invalid_token", "Invalid invitation token")
	}

	user, inv, err := models.AcceptRBACInvitationByToken(c.Context(), h.db, token)
	if err != nil {
		return teamsModelError(c, err)
	}

	team, err := models.GetTeamByID(c.Context(), h.db, inv.TeamID)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "team_lookup_failed", "Failed to load invited team")
	}

	sessionToken, err := signSessionJWT(h.cfg.JWTSecret, user, team)
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "session_failed", "Failed to issue session")
	}

	return c.JSON(fiber.Map{
		"ok":            true,
		"session_token": sessionToken,
		"user": fiber.Map{
			"id":    user.ID.String(),
			"email": user.Email,
			"role":  user.Role,
		},
		"team": fiber.Map{
			"id":   team.ID.String(),
			"name": team.Name.String,
		},
	})
}

// requireTeamMatch parses the :team_id path param and ensures it matches the
// authenticated team in the JWT. Returns the parsed UUID on success, or a
// fiber error (caller returns directly).
func (h *TeamsHandler) requireTeamMatch(c *fiber.Ctx) (uuid.UUID, error) {
	pathTeamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return uuid.Nil, respondError(c, fiber.StatusBadRequest, "invalid_team_id", "Invalid team id")
	}
	authTeamID := middleware.GetTeamID(c)
	if authTeamID == "" {
		return uuid.Nil, respondError(c, fiber.StatusUnauthorized, "unauthorized", "Valid session required")
	}
	if pathTeamID.String() != authTeamID {
		return uuid.Nil, respondError(c, fiber.StatusForbidden, "forbidden", "Cannot act on another team")
	}
	return pathTeamID, nil
}

// serializeInvitation produces the JSON shape returned by the invite endpoints.
// The token is included so owners/admins can re-share an invite link without
// triggering a new email send.
func serializeInvitation(inv *models.RBACInvitation) fiber.Map {
	return fiber.Map{
		"id":         inv.ID.String(),
		"email":      inv.Email,
		"role":       inv.Role,
		"token":      inv.Token,
		"status":     inv.Status(),
		"invited_by": inv.InvitedBy.String(),
		"expires_at": inv.ExpiresAt.UTC().Format(time.RFC3339),
		"created_at": inv.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// teamsModelError maps RBAC-invitation model errors to HTTP responses.
func teamsModelError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, models.ErrInvitationNotFound):
		return respondError(c, fiber.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, models.ErrInvitationExpired),
		errors.Is(err, models.ErrInvitationAlreadyAccepted),
		errors.Is(err, models.ErrInvitationRevoked),
		errors.Is(err, models.ErrInvitationNotPending):
		return respondError(c, fiber.StatusGone, "invitation_invalid", err.Error())
	case errors.Is(err, models.ErrInvitationTokenInvalid):
		return respondError(c, fiber.StatusBadRequest, "invalid_token", err.Error())
	case errors.Is(err, models.ErrInvalidInviteRole):
		return respondError(c, fiber.StatusBadRequest, "invalid_role", err.Error())
	case errors.Is(err, models.ErrDuplicatePendingInvite):
		return respondError(c, fiber.StatusConflict, "duplicate", err.Error())
	case errors.Is(err, models.ErrEmailMismatchInvite):
		return respondError(c, fiber.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, models.ErrLastOwner):
		return respondError(c, fiber.StatusConflict, "last_owner", err.Error())
	default:
		return respondError(c, fiber.StatusInternalServerError, "internal_error", "Request failed")
	}
}
