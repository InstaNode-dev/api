package handlers_test

// admin_customer_notes_test.go — integration coverage for the three
// /api/v1/admin/customers/:team_id/notes + /admin/notes/:note_id endpoints.
// Uses the same fake-auth shim as admin_customers_test.go so we can drive
// the real handler set behind RequireAdmin without minting JWTs.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// adminNotesApp builds a Fiber app wired to NewAdminCustomerNotesHandler
// behind the same fake-auth shim adminApp() uses. Routes match what
// router.go installs:
//
//	GET    /api/v1/admin/customers/:team_id/notes
//	POST   /api/v1/admin/customers/:team_id/notes
//	DELETE /api/v1/admin/notes/:note_id
func adminNotesApp(t *testing.T, db *sql.DB, callerEmail string) *fiber.App {
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

	notesH := handlers.NewAdminCustomerNotesHandler(db)
	adminGroup := app.Group("/api/v1/admin", fakeAuth, middleware.RequireAdmin())
	adminGroup.Get("/customers/:team_id/notes", notesH.ListNotes)
	adminGroup.Post("/customers/:team_id/notes", notesH.CreateNote)
	adminGroup.Delete("/notes/:note_id", notesH.DeleteNote)
	return app
}

// TestAdminNotes_CreateListDelete is the headline integration round-trip:
// create one note → list returns it → delete removes it → list is empty.
// Asserts on the wire shape (id/team_id/body/author_email/created_at) at
// each step so a regression in serialisation is caught here.
func TestAdminNotes_CreateListDelete(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM admin_customer_notes WHERE team_id = $1`, teamID)
	})

	// 1. Create.
	body := "called this customer 2024-05-10, they want pro tier with annual billing"
	status, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/notes",
		map[string]any{"body": body})
	require.Equal(t, http.StatusCreated, status, "create must return 201: %v", resp)
	note, _ := resp["note"].(map[string]any)
	require.NotNil(t, note, "response must carry the created note")
	noteID, _ := note["id"].(string)
	require.NotEmpty(t, noteID, "note id must be non-empty")
	assert.Equal(t, teamID.String(), note["team_id"])
	assert.Equal(t, body, note["body"])
	assert.Equal(t, adminCallerEmail, note["author_email"],
		"author_email must be sourced from the admin's JWT, never the request body")

	// 2. List — must surface the created note.
	status, resp = adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers/"+teamID.String()+"/notes", nil)
	require.Equal(t, http.StatusOK, status)
	notes, _ := resp["notes"].([]any)
	require.Len(t, notes, 1)
	row, _ := notes[0].(map[string]any)
	assert.Equal(t, noteID, row["id"])
	assert.Equal(t, body, row["body"])

	// 3. Delete.
	status, resp = adminDoJSON(t, app, "DELETE",
		"/api/v1/admin/notes/"+noteID, nil)
	require.Equal(t, http.StatusOK, status, "delete must return 200: %v", resp)
	assert.Equal(t, noteID, resp["note_id"])

	// 4. List again — must be empty (hard delete, no tombstone).
	status, resp = adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers/"+teamID.String()+"/notes", nil)
	require.Equal(t, http.StatusOK, status)
	notes, _ = resp["notes"].([]any)
	assert.Empty(t, notes, "delete must be a hard delete — list returns no rows")
}

// TestAdminNotes_ListReturnsNewestFirst — multiple notes on the same team
// must come back newest first. The DB index is (team_id, created_at DESC)
// so this is a single index scan; the assertion guards against a
// regression that drops the ORDER BY or reverses the direction.
func TestAdminNotes_ListReturnsNewestFirst(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")
	t.Cleanup(func() {
		db.Exec(`DELETE FROM admin_customer_notes WHERE team_id = $1`, teamID)
	})

	// Three notes in order. We can't rely on created_at being distinct
	// in fast succession on every platform, so we INSERT directly with
	// explicit created_at values one second apart.
	type seed struct{ body, ts string }
	seeds := []seed{
		{"oldest", "2024-05-08T10:00:00Z"},
		{"middle", "2024-05-09T10:00:00Z"},
		{"newest", "2024-05-10T10:00:00Z"},
	}
	for _, s := range seeds {
		ts, _ := time.Parse(time.RFC3339, s.ts)
		_, err := db.ExecContext(context.Background(), `
			INSERT INTO admin_customer_notes (team_id, body, author_email, created_at)
			VALUES ($1, $2, $3, $4)
		`, teamID, s.body, adminCallerEmail, ts)
		require.NoError(t, err)
	}

	status, resp := adminDoJSON(t, app, "GET",
		"/api/v1/admin/customers/"+teamID.String()+"/notes", nil)
	require.Equal(t, http.StatusOK, status)
	notes, _ := resp["notes"].([]any)
	require.Len(t, notes, 3)
	got := []string{
		notes[0].(map[string]any)["body"].(string),
		notes[1].(map[string]any)["body"].(string),
		notes[2].(map[string]any)["body"].(string),
	}
	assert.Equal(t, []string{"newest", "middle", "oldest"}, got,
		"notes must be returned newest first")
}

// TestAdminNotes_NonAdmin_ListBlocked — a non-admin caller hitting the
// list endpoint must 403 via RequireAdmin BEFORE any DB query runs.
// Identical to the gate-test in admin_customers_test.go but exercised
// against the notes routes specifically — regression-proofing the wiring
// in router.go (the notes endpoints must register inside the
// RequireAdmin-gated group, not outside it).
func TestAdminNotes_NonAdmin_ListBlocked(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminNonAdminEmail)

	teamID, _ := adminSeedTeam(t, db, "hobby")

	cases := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/admin/customers/" + teamID.String() + "/notes", nil},
		{"POST", "/api/v1/admin/customers/" + teamID.String() + "/notes", map[string]any{"body": "x"}},
		{"DELETE", "/api/v1/admin/notes/" + uuid.NewString(), nil},
	}
	for _, tc := range cases {
		status, body := adminDoJSON(t, app, tc.method, tc.path, tc.body)
		assert.Equal(t, http.StatusForbidden, status,
			"%s %s — non-admin must be rejected at the gate", tc.method, tc.path)
		assert.Equal(t, "forbidden", body["error"])
	}
}

// TestAdminNotes_Create_EmptyBody_400 — the body field is required.
// Empty-string and whitespace-only must both 400 with missing_body. The
// model layer also rejects (typed sentinel) so a future move of the
// pre-check to the model side keeps the same external behavior.
func TestAdminNotes_Create_EmptyBody_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")

	for _, body := range []map[string]any{
		{"body": ""},
		{"body": "   \t\n"},
		{}, // no field at all
	} {
		status, resp := adminDoJSON(t, app, "POST",
			"/api/v1/admin/customers/"+teamID.String()+"/notes", body)
		assert.Equal(t, http.StatusBadRequest, status, "body=%v must 400", body)
		assert.Equal(t, "missing_body", resp["error"])
	}
}

// TestAdminNotes_Create_UnknownTeam_404 — POST to a team that doesn't
// exist must 404 with team_not_found, NOT a 503 from the FK violation.
// The handler does an explicit GetTeamByID precheck for this reason.
func TestAdminNotes_Create_UnknownTeam_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)

	status, body := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+uuid.NewString()+"/notes",
		map[string]any{"body": "ghost note"})
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "team_not_found", body["error"])
}

// TestAdminNotes_Delete_Unknown_404 — DELETE on a note id that doesn't
// exist must 404 with note_not_found (typed sentinel through the model).
func TestAdminNotes_Delete_Unknown_404(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)

	status, body := adminDoJSON(t, app, "DELETE",
		"/api/v1/admin/notes/"+uuid.NewString(), nil)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, "note_not_found", body["error"])
}

// TestAdminNotes_Create_TooLong_400 — body > 8KB must be rejected with
// body_too_long. Guards the model's typed-sentinel-→-400 mapping.
func TestAdminNotes_Create_TooLong_400(t *testing.T) {
	db, cleanup := adminAppNeedsDB(t)
	defer cleanup()
	t.Setenv("ADMIN_EMAILS", adminCallerEmail)
	app := adminNotesApp(t, db, adminCallerEmail)
	teamID, _ := adminSeedTeam(t, db, "hobby")

	// 8KB + 1 byte of 'x'.
	huge := bytes.Repeat([]byte("x"), 8*1024+1)
	status, resp := adminDoJSON(t, app, "POST",
		"/api/v1/admin/customers/"+teamID.String()+"/notes",
		map[string]any{"body": string(huge)})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "body_too_long", resp["error"])
}

// adminNotesDoJSON is a 1-call wrapper around adminDoJSON kept here so the
// notes test file can be relocated or duplicated without leaning on the
// admin_customers_test.go helper layout. Unused once cross-file
// dependencies stabilize — but cheap to keep.
//
//nolint:unused // reserved for future use
func adminNotesDoJSON(t *testing.T, app *fiber.App, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		out = map[string]any{}
	}
	return resp.StatusCode, out
}
