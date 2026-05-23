package handlers_test

// resource_final_test.go — FINAL coverage pass for resource.go. Closes the
// mid-handler DB-error arms of Pause / Resume / RotateCredentials that the rbw
// slice leaves open. Uses openFaultDB (staged failAfter): the early auth +
// ownership lookups succeed, then the targeted query errors. The provider is
// nil (no customer DB configured) so pauseProvider/resumeProvider are no-ops —
// the handler still exercises the full DB-flip + rollback codepath.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// resourceFaultApp wires the Pause/Resume/Rotate routes against a faultdb-backed
// ResourceHandler with a Locals-pinned team/user.
func resourceFaultApp(t *testing.T, db *sql.DB, teamID string) *fiber.App {
	t.Helper()
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandler(db, nil, cfg, plans.Default(), nil, nil)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": e.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	app.Post("/r/:id/pause", h.Pause)
	app.Post("/r/:id/resume", h.Resume)
	app.Post("/r/:id/rotate", h.RotateCredentials)
	return app
}

func rfSeedActivePG(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, 'postgres', 'pro', 'active', 'ciphertext')
		 RETURNING token::text`, teamID).Scan(&token))
	return token
}

func rfSeedPausedPG(t *testing.T, db *sql.DB, teamID string) string {
	t.Helper()
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, 'postgres', 'pro', 'paused', 'ciphertext')
		 RETURNING token::text`, teamID).Scan(&token))
	return token
}

func rfPost(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, path, nil), 10000)
	require.NoError(t, err)
	return resp
}

func rfErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var m map[string]any
	_ = decodeJSON(resp, &m)
	if s, ok := m["error"].(string); ok {
		return s
	}
	return ""
}

// Pause: GetResourceByToken errors → fetch_failed (resource.go:567). failAfter=0.
func TestResourceFinal_Pause_LookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedActivePG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 0), teamID)
	resp := rfPost(t, app, "/r/"+token+"/pause")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", rfErr(t, resp))
}

// Pause: GetTeamByID errors → team_lookup_failed (resource.go:595). resource(1)
// succeeds, team(2) errors. failAfter=1.
func TestResourceFinal_Pause_TeamLookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedActivePG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 1), teamID)
	resp := rfPost(t, app, "/r/"+token+"/pause")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", rfErr(t, resp))
}

// Pause: PauseResource UPDATE errors → pause_failed + rollback (resource.go:635).
// resource(1) + team(2) succeed, the pauseProvider is a no-op (nil customer DB),
// then PauseResource(3) errors. failAfter=2.
func TestResourceFinal_Pause_DBFlipError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedActivePG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 2), teamID)
	resp := rfPost(t, app, "/r/"+token+"/pause")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "pause_failed", rfErr(t, resp))
}

// Resume: GetResourceByToken errors → fetch_failed (resource.go Resume lookup
// arm). failAfter=0.
func TestResourceFinal_Resume_LookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedPausedPG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 0), teamID)
	resp := rfPost(t, app, "/r/"+token+"/resume")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", rfErr(t, resp))
}

// Resume: ResumeResource UPDATE errors → resume_failed. resource(1) succeeds,
// resumeProvider no-op, ResumeResource(2) errors. failAfter=1.
func TestResourceFinal_Resume_DBFlipError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedPausedPG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 1), teamID)
	resp := rfPost(t, app, "/r/"+token+"/resume")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// RotateCredentials: GetResourceByToken errors → fetch_failed. failAfter=0.
func TestResourceFinal_Rotate_LookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	token := rfSeedActivePG(t, seedDB, teamID)

	app := resourceFaultApp(t, openFaultDB(t, 0), teamID)
	resp := rfPost(t, app, "/r/"+token+"/rotate")
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", rfErr(t, resp))
}
