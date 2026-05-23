package handlers_test

// audit_final_test.go — FINAL coverage pass for audit.go's List / ListCSV
// DB-error arms via a faultdb-backed handler.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

func auditFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, Environment: "test"}
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
	h := handlers.NewAuditHandler(db)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/audit", h.List)
	api.Get("/audit.csv", h.ListCSV)
	return app
}

func auditJWT(t *testing.T, db *sql.DB) string {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`, teamID, email).Scan(&userID))
	return testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

// List: ListAuditEventsByTeam errors → db_failed (audit.go:246). failAfter=0.
func TestAuditFinal_List_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	jwt := auditJWT(t, seedDB)

	app := auditFaultApp(t, openFaultDB(t, 0))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ListCSV: ListAuditEventsByTeam errors → db_failed (audit.go:313). failAfter=0.
func TestAuditFinal_ListCSV_DBError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	jwt := auditJWT(t, seedDB)

	app := auditFaultApp(t, openFaultDB(t, 0))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit.csv", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
