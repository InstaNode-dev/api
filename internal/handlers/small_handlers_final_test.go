package handlers_test

// small_handlers_final_test.go — FINAL coverage pass for small handler arms:
//   - whoami.Get: nil-db early return + email-enrichment success.
//   - usage_wall.GetWall: db_failed via faultdb.
//   - deploys_audit.List: db_failed via faultdb.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// whoami.Get with a nil DB → early return without enrichment (whoami.go:55).
func TestWhoamiFinal_NilDB_EarlyReturn(t *testing.T) {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	h := handlers.NewWhoamiHandler(nil)
	app.Get("/whoami", h.Get)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/whoami", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// whoami.Get with a real team + user → tier + email enrichment (whoami.go:63,74).
func TestWhoamiFinal_Enrichment(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`, teamID, email).Scan(&userID))

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, userID)
		return c.Next()
	})
	h := handlers.NewWhoamiHandler(db)
	app.Get("/whoami", h.Get)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/whoami", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var m map[string]any
	require.NoError(t, decodeJSON(resp, &m))
	assert.Equal(t, "pro", m["tier"])
	assert.Equal(t, email, m["email"])
}

// usage_wall.GetWall: the usage query errors → db_failed (usage_wall.go:118).
// team-tier check(1) errors-or-misses, then the usage query(2) errors. Use a
// non-team tier so the early-return is skipped; failAfter=1 makes the usage
// query error.
func TestUsageWallFinal_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, seedDB, "pro"))

	app := newUsageWallApp(t, openFaultDB(t, 1), teamID)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/usage/wall", nil), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// deploys_audit.List: the list query errors → db_failed (deploys_audit.go:121).
func TestDeploysAuditFinal_DBError_503(t *testing.T) {
	t.Setenv(middleware.AdminEmailsEnvVar, deploysAuditAdminEmail)
	app := deploysAuditApp(t, openFaultDB(t, 0), deploysAuditAdminEmail)
	status, _ := deploysAuditDoGET(t, app, "/api/v1/admin/deploys")
	assert.Equal(t, http.StatusServiceUnavailable, status)
}
