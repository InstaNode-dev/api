package handlers

// audit.go — GET /api/v1/audit — per-team audit log for the dashboard's
// Recent Activity feed.
//
// Response shape:
//
//	{
//	  "ok":    true,
//	  "items": [
//	    {
//	      "id":            "<uuid>",
//	      "actor":         "agent",
//	      "kind":          "provision",
//	      "resource_type": "postgres",
//	      "resource_id":   "<uuid|null>",
//	      "summary":       "agent provisioned <strong>postgres</strong> <code>1234abcd</code>",
//	      "metadata":      { ... },
//	      "at":            "2026-05-10T12:34:56Z"
//	    }
//	  ]
//	}
//
// `at` mirrors the dashboard's ActivityItem.at field. `summary` is
// rendered via dangerouslySetInnerHTML on the dashboard side — writers
// must therefore only embed values that are safe (UUIDs, fixed strings).

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// auditDefaultLimit is the default `?limit` when the caller doesn't
// pass one. Matches the dashboard's Recent Activity feed page size.
const auditDefaultLimit = 20

// auditMaxLimitQuery caps `?limit` regardless of what the client asks
// for. Mirrors models.auditMaxLimit so callers can't bypass it.
const auditMaxLimitQuery = 200

// AuditHandler serves GET /api/v1/audit.
type AuditHandler struct {
	db *sql.DB
}

// NewAuditHandler constructs an AuditHandler.
func NewAuditHandler(db *sql.DB) *AuditHandler {
	return &AuditHandler{db: db}
}

// List handles GET /api/v1/audit?limit=20&kind=...
func (h *AuditHandler) List(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(middleware.GetTeamID(c))
	if err != nil {
		return respondError(c, fiber.StatusUnauthorized, "unauthorized", "Authentication required")
	}

	limit := auditDefaultLimit
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > auditMaxLimitQuery {
		limit = auditMaxLimitQuery
	}

	kindFilter := strings.TrimSpace(c.Query("kind"))

	events, err := models.ListAuditEventsByTeam(c.Context(), h.db, teamID, limit, kindFilter)
	if err != nil {
		slog.Error("audit.list.failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed",
			"Failed to list audit events")
	}

	items := make([]fiber.Map, 0, len(events))
	for _, ev := range events {
		item := fiber.Map{
			"id":            ev.ID,
			"actor":         ev.Actor,
			"kind":          ev.Kind,
			"resource_type": ev.ResourceType,
			"resource_id":   nil,
			"summary":       ev.Summary,
			"metadata":      nil,
			"at":            ev.CreatedAt,
		}
		if ev.ResourceID.Valid {
			item["resource_id"] = ev.ResourceID.UUID
		}
		if len(ev.Metadata) > 0 {
			// Pass the raw JSONB through. If it fails to parse (shouldn't,
			// since we wrote it), fall back to nil rather than 500.
			var meta interface{}
			if err := json.Unmarshal(ev.Metadata, &meta); err == nil {
				item["metadata"] = meta
			}
		}
		items = append(items, item)
	}

	return c.JSON(fiber.Map{"ok": true, "items": items})
}
