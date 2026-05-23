package handlers_test

// admin_promos_audit_residual_test.go — residual coverage for
// admin_promos_audit.go (86.7% → ≥95%) and admin_customer_notes.go
// (93.5% → ≥95%). Targets:
//
//   - Audit invalid_since → 400 (lines 141-144).
//   - Audit query_failed → 503 (167-171), via brokenDB.
//   - Stats compute closure error + handler db_failed (262-264, 272-276),
//     via brokenDB + nil cache (fall-through to live compute).
//   - CreateNote create_failed → 503 (170-171), via brokenDB.

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// sqlmockNewRegexp constructs a regexp-matcher sqlmock DB. Shared by the
// residual tests that need GetTeamByID-then-INSERT sequences.
func sqlmockNewRegexp(t *testing.T) (*sql.DB, sqlmock.Sqlmock, error) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	return db, mock, err
}

// TestPromoAudit_InvalidSince_400 hits the invalid-since arm (141-144).
func TestPromoAudit_InvalidSince_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := promoAuditApp(t, db, nil, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/promos/audit?since=not-a-date", nil)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_since", body["error"])
}

// TestPromoAudit_QueryFailed_BrokenDB hits the query_failed arm (167-171).
func TestPromoAudit_QueryFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := promoAuditApp(t, brokenDB(t), nil, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/promos/audit", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// TestPromoStats_ComputeFailed_BrokenDB hits the Stats compute-failed closure
// (262-264) and handler db_failed arm (272-276). nil rdb means the cache
// helper falls through to a live compute, which errors on the closed DB.
func TestPromoStats_ComputeFailed_BrokenDB(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := promoAuditApp(t, brokenDB(t), nil, adminCallerEmail)
	status, body := adminDoJSON(t, app, "GET", "/api/v1/admin/promos/stats", nil)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}

// ── admin_customer_notes.go ──────────────────────────────────────────────────

// notesAppWithDB wires CreateNote against an arbitrary DB so the
// create_failed arm can be driven with a brokenDB. (The team-exists check
// runs first; on a brokenDB GetTeamByID itself fails with db_failed, which
// covers the team-query arm — to reach the CreateAdminCustomerNote-failed arm
// at 170-171 we need GetTeamByID to succeed but the INSERT to fail, so we
// seed a real team in a live DB then close the DB mid-flight is impossible;
// instead we use sqlmock: team lookup OK, note INSERT errors.)
func notesAppWithDB(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	fakeAuth := func(c *fiber.Ctx) error {
		if callerEmail != "" {
			c.Locals(middleware.LocalKeyEmail, callerEmail)
		}
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	}
	h := handlers.NewAdminCustomerNotesHandler(db)
	g := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	g.Post("/customers/:team_id/notes", h.CreateNote)
	return app
}

// TestAdminNotes_CreateFailed_Sqlmock hits the create_failed arm (170-171):
// GetTeamByID succeeds, the note INSERT errors with a non-validation error.
func TestAdminNotes_CreateFailed_Sqlmock(t *testing.T) {
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	db, mock, err := sqlmockNewRegexp(t)
	defer db.Close()
	tid := uuid.New()
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).WithArgs(tid).WillReturnRows(adminTeamRow(tid, "hobby"))
	// CreateAdminCustomerNote uses a QueryRow INSERT...RETURNING — generic error.
	mock.ExpectQuery(`INSERT INTO admin_customer_notes`).WillReturnError(errors.New("note boom"))
	_ = err

	app := notesAppWithDB(t, db, adminCallerEmail)
	status, body := adminDoJSON(t, app, "POST", "/api/v1/admin/customers/"+tid.String()+"/notes",
		map[string]any{"body": "a real note"})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "db_failed", body["error"])
}
