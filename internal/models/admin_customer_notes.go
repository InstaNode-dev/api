package models

// admin_customer_notes.go — free-text notes per team, written by platform
// admins. Surfaces on the admin Customer Detail drawer so the founder can
// jot "called this customer 2024-05-10, they want pro tier with annual
// billing" without leaving the dashboard.
//
// Storage shape: dedicated `admin_customer_notes` table (migration 024).
// Hard delete on DELETE — notes are reversible by re-typing, so the soft-
// delete bookkeeping (an `is_deleted` column, paranoid filtering on every
// read) buys nothing operationally. The author_email column is
// denormalized rather than a FK to users so deleting an admin's user row
// doesn't blow up audit coherence; same pattern as audit_log.actor.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AdminCustomerNoteMaxBody bounds the user-supplied body to keep one note
// from monopolising a row. 8KB is enough for paragraph-length context
// ("called this customer 2024-05-10, they want pro tier with annual
// billing…") and well under Postgres TOAST overflow.
const AdminCustomerNoteMaxBody = 8 * 1024

// ErrAdminCustomerNoteEmpty is returned by CreateAdminCustomerNote when
// the body is empty/whitespace-only. Validated in the model layer so
// the handler doesn't have to repeat the check.
var ErrAdminCustomerNoteEmpty = errors.New("models.CreateAdminCustomerNote: body must be non-empty")

// ErrAdminCustomerNoteTooLong is returned when the body exceeds
// AdminCustomerNoteMaxBody bytes.
var ErrAdminCustomerNoteTooLong = errors.New("models.CreateAdminCustomerNote: body exceeds 8KB cap")

// ErrAdminCustomerNoteNotFound is returned by DeleteAdminCustomerNote
// when the note ID doesn't exist. Distinct sentinel so the handler can
// branch to 404 vs 503 cleanly.
var ErrAdminCustomerNoteNotFound = errors.New("models.DeleteAdminCustomerNote: note not found")

// AdminCustomerNote mirrors one row of the admin_customer_notes table.
type AdminCustomerNote struct {
	ID          uuid.UUID
	TeamID      uuid.UUID
	Body        string
	AuthorEmail string
	CreatedAt   time.Time
}

// CreateAdminCustomerNoteParams bundles the inputs for inserting a note.
type CreateAdminCustomerNoteParams struct {
	TeamID      uuid.UUID
	Body        string
	AuthorEmail string
}

// CreateAdminCustomerNote inserts one row and returns the populated note.
// Validates body length here (not at the DB layer) so the error is a
// typed sentinel callers can branch on without parsing PG error codes.
func CreateAdminCustomerNote(ctx context.Context, db *sql.DB, p CreateAdminCustomerNoteParams) (*AdminCustomerNote, error) {
	body := strings.TrimSpace(p.Body)
	if body == "" {
		return nil, ErrAdminCustomerNoteEmpty
	}
	if len(body) > AdminCustomerNoteMaxBody {
		return nil, ErrAdminCustomerNoteTooLong
	}

	out := &AdminCustomerNote{
		TeamID:      p.TeamID,
		Body:        body,
		AuthorEmail: p.AuthorEmail,
	}
	err := db.QueryRowContext(ctx, `
		INSERT INTO admin_customer_notes (team_id, body, author_email)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`, p.TeamID, body, p.AuthorEmail).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("models.CreateAdminCustomerNote: %w", err)
	}
	return out, nil
}

// ListAdminCustomerNotes returns every note for a team, newest first.
// Capped at limit rows (clamped to a sensible default + max here so the
// handler doesn't have to repeat the bounds-check). Unlike the audit log
// this isn't paginated — the per-team note volume is expected to stay in
// the dozens.
func ListAdminCustomerNotes(ctx context.Context, db *sql.DB, teamID uuid.UUID, limit int) ([]*AdminCustomerNote, error) {
	if limit <= 0 {
		limit = adminCustomerNotesDefaultLimit
	}
	if limit > adminCustomerNotesMaxLimit {
		limit = adminCustomerNotesMaxLimit
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, body, author_email, created_at
		FROM admin_customer_notes
		WHERE team_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, teamID, limit)
	if err != nil {
		return nil, fmt.Errorf("models.ListAdminCustomerNotes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]*AdminCustomerNote, 0)
	for rows.Next() {
		n := &AdminCustomerNote{}
		if err := rows.Scan(&n.ID, &n.TeamID, &n.Body, &n.AuthorEmail, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("models.ListAdminCustomerNotes scan: %w", err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListAdminCustomerNotes rows: %w", err)
	}
	return out, nil
}

// DeleteAdminCustomerNote hard-deletes one note by id. Returns
// ErrAdminCustomerNoteNotFound when no row matched — distinct sentinel so
// the handler can map cleanly to 404. Soft-delete was considered and
// rejected: notes are reversible by re-typing, so the column +
// always-filter overhead buys nothing.
func DeleteAdminCustomerNote(ctx context.Context, db *sql.DB, noteID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		DELETE FROM admin_customer_notes WHERE id = $1
	`, noteID)
	if err != nil {
		return fmt.Errorf("models.DeleteAdminCustomerNote: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("models.DeleteAdminCustomerNote rows_affected: %w", err)
	}
	if n == 0 {
		return ErrAdminCustomerNoteNotFound
	}
	return nil
}

// adminCustomerNotesDefaultLimit / adminCustomerNotesMaxLimit cap the
// ListAdminCustomerNotes query. Per-team note volume is expected to stay
// in the dozens; if a team ever has 200+ notes the operator should switch
// to the audit log instead.
const (
	adminCustomerNotesDefaultLimit = 50
	adminCustomerNotesMaxLimit     = 200
)
