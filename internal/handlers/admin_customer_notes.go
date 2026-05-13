package handlers

// admin_customer_notes.go — three handlers backing the admin Customer
// Detail drawer's free-text notes:
//
//   GET    /api/v1/admin/customers/:team_id/notes  → list notes for team
//   POST   /api/v1/admin/customers/:team_id/notes  → create a note
//   DELETE /api/v1/admin/notes/:note_id            → hard-delete a note
//
// All three sit behind the same RequireAdmin gate as the rest of the
// admin/customers/* surface (see admin_customers.go for the gate
// rationale). DELETE is a hard delete because notes are reversible by
// re-typing — see migration 024 for the soft-delete trade-off.
//
// The list / create handlers receive :team_id in the URL (so they can be
// nested under /admin/customers/...). The delete handler takes only
// :note_id because notes are globally addressable by id; the admin must
// already have hit the list endpoint to know which id to delete, so the
// team_id is recoverable from the row itself if a future audit/log
// consumer needs it.

import (
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
)

// AdminCustomerNotesHandler serves the three /admin/.../notes endpoints.
// Slim wrapper around models.* — no Razorpay / no plans Registry needed,
// so the constructor is just the DB handle.
type AdminCustomerNotesHandler struct {
	db *sql.DB
}

// NewAdminCustomerNotesHandler constructs the handler.
func NewAdminCustomerNotesHandler(db *sql.DB) *AdminCustomerNotesHandler {
	return &AdminCustomerNotesHandler{db: db}
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire shape
// ─────────────────────────────────────────────────────────────────────────────

// adminNoteWire is the per-row response shape. team_id is surfaced on
// every wire row (list AND create) so the dashboard's "create + redirect
// to detail" UI flow has the team id in the body without re-reading the
// URL. RFC3339 created_at — clients parse it the same way they parse the
// rest of the API.
type adminNoteWire struct {
	ID          string `json:"id"`
	TeamID      string `json:"team_id"`
	Body        string `json:"body"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
}

// toAdminNoteWire converts a *models.AdminCustomerNote into the JSON
// shape. Centralised so future schema additions (an edited_at column, a
// redacted bool) flow through one helper.
func toAdminNoteWire(n *models.AdminCustomerNote) adminNoteWire {
	return adminNoteWire{
		ID:          n.ID.String(),
		TeamID:      n.TeamID.String(),
		Body:        n.Body,
		AuthorEmail: n.AuthorEmail,
		CreatedAt:   n.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v1/admin/customers/:team_id/notes — list notes
// ─────────────────────────────────────────────────────────────────────────────

// ListNotes handles GET /api/v1/admin/customers/:team_id/notes.
func (h *AdminCustomerNotesHandler) ListNotes(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	notes, err := models.ListAdminCustomerNotes(c.Context(), h.db, teamID, 0)
	if err != nil {
		slog.Error("admin.customers.notes.list_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to list notes")
	}

	out := make([]adminNoteWire, 0, len(notes))
	for _, n := range notes {
		out = append(out, toAdminNoteWire(n))
	}
	return c.JSON(fiber.Map{
		"ok":    true,
		"notes": out,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v1/admin/customers/:team_id/notes — create a note
// ─────────────────────────────────────────────────────────────────────────────

// adminCreateNoteRequest is the JSON body for POST notes.
type adminCreateNoteRequest struct {
	Body string `json:"body"`
}

// CreateNote handles POST /api/v1/admin/customers/:team_id/notes.
//
// Body validation lives in models.CreateAdminCustomerNote (typed sentinels
// for empty / too-long) so the handler just maps sentinels → status codes.
// The author_email is sourced from the admin's JWT email (populated by
// RequireAuth on the locals) — never read from the request body. That
// boundary stops a malicious admin from impersonating another admin in
// the notes ledger.
//
// A team_not_found 404 is produced by checking up-front via
// models.GetTeamByID rather than relying on the FK violation surface —
// the explicit lookup gives a clean error_code AND keeps the DB layer's
// fmt.Errorf wrapping out of the response.
func (h *AdminCustomerNotesHandler) CreateNote(c *fiber.Ctx) error {
	teamID, err := uuid.Parse(c.Params("team_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_team_id", "team_id must be a UUID")
	}

	var req adminCreateNoteRequest
	if err := c.BodyParser(&req); err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_body", "JSON body required")
	}
	body := strings.TrimSpace(req.Body)
	// Pre-check empty so the typed-sentinel branch is the only path to a
	// 400, not a fall-through to "db_failed" if the model rejected after
	// a partial commit.
	if body == "" {
		return respondError(c, fiber.StatusBadRequest, "missing_body", "body is required")
	}

	// Verify the team exists before the INSERT so we surface 404 with a
	// clean error_code (not a generic 503 "db_failed" from the FK violation
	// the model would otherwise hit).
	if _, err := models.GetTeamByID(c.Context(), h.db, teamID); err != nil {
		var nf *models.ErrTeamNotFound
		if errors.As(err, &nf) {
			return respondError(c, fiber.StatusNotFound, "team_not_found", "no such team")
		}
		slog.Error("admin.customers.notes.team_query_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to load team")
	}

	adminEmail := middleware.GetEmail(c)

	note, err := models.CreateAdminCustomerNote(c.Context(), h.db, models.CreateAdminCustomerNoteParams{
		TeamID:      teamID,
		Body:        body,
		AuthorEmail: adminEmail,
	})
	if err != nil {
		switch {
		case errors.Is(err, models.ErrAdminCustomerNoteEmpty):
			return respondError(c, fiber.StatusBadRequest, "missing_body", "body is required")
		case errors.Is(err, models.ErrAdminCustomerNoteTooLong):
			return respondError(c, fiber.StatusBadRequest, "body_too_long", "body exceeds 8KB cap")
		}
		slog.Error("admin.customers.notes.create_failed", "error", err, "team_id", teamID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to create note")
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"ok":   true,
		"note": toAdminNoteWire(note),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /api/v1/admin/notes/:note_id — hard-delete a note
// ─────────────────────────────────────────────────────────────────────────────

// DeleteNote handles DELETE /api/v1/admin/notes/:note_id.
//
// Hard delete (not soft) — notes are reversible by re-typing, so the
// always-filter / paranoid-read overhead a tombstone column requires
// buys nothing operationally. See migration 024's comment.
func (h *AdminCustomerNotesHandler) DeleteNote(c *fiber.Ctx) error {
	noteID, err := uuid.Parse(c.Params("note_id"))
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "invalid_note_id", "note_id must be a UUID")
	}
	if err := models.DeleteAdminCustomerNote(c.Context(), h.db, noteID); err != nil {
		if errors.Is(err, models.ErrAdminCustomerNoteNotFound) {
			return respondError(c, fiber.StatusNotFound, "note_not_found", "no such note")
		}
		slog.Error("admin.customers.notes.delete_failed", "error", err, "note_id", noteID)
		return respondError(c, fiber.StatusServiceUnavailable, "db_failed", "Failed to delete note")
	}
	return c.JSON(fiber.Map{
		"ok":      true,
		"note_id": noteID.String(),
	})
}
