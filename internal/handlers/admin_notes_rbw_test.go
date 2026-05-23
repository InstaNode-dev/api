package handlers_test

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// notesApp mounts the three note routes behind a shim that sets the admin
// email Local (CreateNote reads middleware.GetEmail).
func notesApp(h *handlers.AdminCustomerNotesHandler, email string) *fiber.App {
	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error {
		if errors.Is(err, handlers.ErrResponseWritten) {
			return nil
		}
		return fiber.DefaultErrorHandler(c, err)
	}})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyEmail, email)
		return c.Next()
	})
	app.Get("/n/:team_id", h.ListNotes)
	app.Post("/n/:team_id", h.CreateNote)
	app.Delete("/n/:note_id", h.DeleteNote)
	return app
}

func noteReq(t *testing.T, app *fiber.App, method, path, body string) int {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func TestAdminNotes_InvalidIDs(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	app := notesApp(handlers.NewAdminCustomerNotesHandler(db), "admin@x.com")
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "GET", "/n/not-a-uuid", ""))
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "POST", "/n/not-a-uuid", `{"body":"x"}`))
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "DELETE", "/n/not-a-uuid", ""))
}

func TestAdminNotes_CreateValidation(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	app := notesApp(handlers.NewAdminCustomerNotesHandler(db), "admin@x.com")

	// invalid body (not JSON)
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "POST", "/n/"+team, `{not json`))
	// missing body
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "POST", "/n/"+team, `{"body":"   "}`))
	// body too long (> 8KB)
	big := `{"body":"` + strings.Repeat("a", 9000) + `"}`
	require.Equal(t, fiber.StatusBadRequest, noteReq(t, app, "POST", "/n/"+team, big))
	// success → 201
	require.Equal(t, fiber.StatusCreated, noteReq(t, app, "POST", "/n/"+team, `{"body":"a real note"}`))
}

func TestAdminNotes_TeamNotFound(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	app := notesApp(handlers.NewAdminCustomerNotesHandler(db), "admin@x.com")
	// valid UUID, no team row → 404
	require.Equal(t, fiber.StatusNotFound, noteReq(t, app, "POST", "/n/"+uuid.NewString(), `{"body":"hi"}`))
}

func TestAdminNotes_NoteNotFound(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	app := notesApp(handlers.NewAdminCustomerNotesHandler(db), "admin@x.com")
	require.Equal(t, fiber.StatusNotFound, noteReq(t, app, "DELETE", "/n/"+uuid.NewString(), ""))
}

func TestAdminNotes_DBError(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	dbClean() // close → all queries error
	app := notesApp(handlers.NewAdminCustomerNotesHandler(db), "admin@x.com")
	require.Equal(t, fiber.StatusServiceUnavailable, noteReq(t, app, "GET", "/n/"+team, ""))
	require.Equal(t, fiber.StatusServiceUnavailable, noteReq(t, app, "POST", "/n/"+team, `{"body":"x"}`))
	require.Equal(t, fiber.StatusServiceUnavailable, noteReq(t, app, "DELETE", "/n/"+uuid.NewString(), ""))
}
