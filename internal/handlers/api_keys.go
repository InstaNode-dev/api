package handlers

// api_keys.go — Personal Access Token CRUD.
//
// Routes (registered in router.go):
//   POST   /api/v1/auth/api-keys           create (returns plaintext ONCE)
//   GET    /api/v1/auth/api-keys           list (no plaintext)
//   DELETE /api/v1/auth/api-keys/:id       revoke
//
// Plaintext is shown only in the create response. The DB stores SHA-256
// of the plaintext; revoking is a soft-set of revoked_at = now().

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// APIKeysHandler serves /api/v1/auth/api-keys.
type APIKeysHandler struct {
	db *sql.DB
}

func NewAPIKeysHandler(db *sql.DB) *APIKeysHandler {
	return &APIKeysHandler{db: db}
}

type createAPIKeyBody struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

// Create handles POST /api/v1/auth/api-keys.
// Returns the plaintext key exactly once — the response is the only place
// the founder will ever see it.
func (h *APIKeysHandler) Create(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	createdBy := uuid.NullUUID{}
	if uidStr := middleware.GetUserID(c); uidStr != "" {
		if u, err := uuid.Parse(uidStr); err == nil {
			createdBy = uuid.NullUUID{UUID: u, Valid: true}
		}
	}

	// Reject PAT creating another PAT — PATs are bound to a creator user.
	// Without one, the audit trail breaks.
	if !createdBy.Valid {
		return respondError(c, fiber.StatusForbidden, "forbidden",
			"PAT creation requires a user session, not another PAT")
	}

	var body createAPIKeyBody
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body",
			"Body must be valid JSON: {\"name\":\"my-laptop\",\"scopes\":[\"read\",\"write\"]}")
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_name",
			"Field 'name' is required (e.g. 'laptop', 'github-actions')")
	}
	if len(body.Name) > 120 {
		return respondError(c, fiber.StatusBadRequest, "name_too_long",
			"Field 'name' must be 120 characters or fewer")
	}

	// Validate scopes — only 'read' / 'write' / 'admin' are honored.
	for _, s := range body.Scopes {
		switch strings.ToLower(s) {
		case "read", "write", "admin":
			// ok
		default:
			return respondError(c, fiber.StatusBadRequest, "invalid_scope",
				"Scopes must be one of: read, write, admin")
		}
	}

	plaintext, err := models.GenerateAPIKeyPlaintext()
	if err != nil {
		slog.Error("api_keys.create.generate_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusInternalServerError, "generate_failed",
			"Failed to generate token bytes")
	}
	hash := models.HashAPIKey(plaintext)

	row, err := models.CreateAPIKey(c.Context(), h.db, teamID, createdBy, body.Name, hash, body.Scopes)
	if err != nil {
		slog.Error("api_keys.create.db_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to store API key")
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":         true,
		"id":         row.ID,
		"name":       row.Name,
		"scopes":     row.Scopes,
		"created_at": row.CreatedAt,
		"key":        plaintext,
		"note":       "Save this key now — it will not be shown again. Use as: Authorization: Bearer " + plaintext,
	})
}

// List handles GET /api/v1/auth/api-keys. Returns metadata only.
func (h *APIKeysHandler) List(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	keys, err := models.ListAPIKeysByTeam(c.Context(), h.db, teamID)
	if err != nil {
		slog.Error("api_keys.list.failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list API keys")
	}
	items := make([]fiber.Map, 0, len(keys))
	for _, k := range keys {
		item := fiber.Map{
			"id":           k.ID,
			"name":         k.Name,
			"scopes":       k.Scopes,
			"created_at":   k.CreatedAt,
			"last_used_at": nil,
			"revoked":      k.RevokedAt.Valid,
		}
		if k.LastUsedAt.Valid {
			item["last_used_at"] = k.LastUsedAt.Time
		}
		items = append(items, item)
	}
	return c.JSON(fiber.Map{"ok": true, "items": items})
}

// Revoke handles DELETE /api/v1/auth/api-keys/:id.
func (h *APIKeysHandler) Revoke(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_id", "Path parameter must be a UUID")
	}
	if err := models.RevokeAPIKey(c.Context(), h.db, teamID, id); err != nil {
		if errors.Is(err, models.ErrAPIKeyNotFound) {
			return respondError(c, fiber.StatusNotFound, "not_found", "API key not found")
		}
		slog.Error("api_keys.revoke.failed", "error", err, "team_id", teamID, "id", id)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to revoke API key")
	}
	return c.JSON(fiber.Map{"ok": true, "id": id})
}
