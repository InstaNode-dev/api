package handlers

// whoami.go — GET /api/v1/whoami
//
// Lightweight identity probe for agents: confirms the bearer token is valid
// and exposes which team + tier it grants access to. Returning 404 on an
// arbitrary missing endpoint (the historical /api/v1/team behaviour) made
// agents loop on token-mint logic when the real problem was that the
// endpoint didn't exist. /whoami is the canonical "am I auth'd" endpoint.

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// WhoamiHandler holds the DB handle needed to enrich the response with the
// team's current plan_tier (so the agent doesn't need a second hop to /billing).
type WhoamiHandler struct {
	db *sql.DB
}

// NewWhoamiHandler constructs the handler.
func NewWhoamiHandler(db *sql.DB) *WhoamiHandler {
	return &WhoamiHandler{db: db}
}

// Get handles GET /api/v1/whoami. The /api/v1 group already enforces
// RequireAuth, so if execution reaches this function the token is valid.
func (h *WhoamiHandler) Get(c *fiber.Ctx) error {
	userIDStr := middleware.GetUserID(c)
	teamIDStr := middleware.GetTeamID(c)

	resp := fiber.Map{
		"ok":      true,
		"user_id": userIDStr,
		"team_id": teamIDStr,
	}

	// Best-effort enrichment with team_name and plan_tier — never blocks the
	// response. If the DB call fails, the agent still gets the identity bits
	// it can act on.
	if teamUUID, err := uuid.Parse(teamIDStr); err == nil && h.db != nil {
		if team, err := models.GetTeamByID(c.Context(), h.db, teamUUID); err == nil && team != nil {
			resp["plan_tier"] = team.PlanTier
			if team.Name.Valid && team.Name.String != "" {
				resp["team_name"] = team.Name.String
			}
		}
	}

	return c.JSON(resp)
}
