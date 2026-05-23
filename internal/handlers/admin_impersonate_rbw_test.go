package handlers_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

func impersonateApp(h *handlers.AdminImpersonateHandler, email string) *fiber.App {
	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error {
		if errors.Is(err, handlers.ErrResponseWritten) {
			return nil
		}
		return fiber.DefaultErrorHandler(c, err)
	}})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyEmail, email); return c.Next() })
	app.Post("/imp/:team_id", h.Impersonate)
	return app
}

func impReq(t *testing.T, app *fiber.App, path string) int {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("POST", path, nil), 10000)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

func TestImpersonate_InvalidTeamID(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	cfg := &config.Config{Environment: "test", JWTSecret: testhelpers.TestJWTSecret}
	app := impersonateApp(handlers.NewAdminImpersonateHandler(db, cfg), "admin@x.com")
	require.Equal(t, fiber.StatusBadRequest, impReq(t, app, "/imp/not-a-uuid"))
}

func TestImpersonate_TeamNotFound(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	cfg := &config.Config{Environment: "test", JWTSecret: testhelpers.TestJWTSecret}
	app := impersonateApp(handlers.NewAdminImpersonateHandler(db, cfg), "admin@x.com")
	require.Equal(t, fiber.StatusNotFound, impReq(t, app, "/imp/"+uuid.NewString()))
}

func TestImpersonate_DBError(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	dbClean() // closed → GetTeamByID errors (non-not-found) → db_failed
	cfg := &config.Config{Environment: "test", JWTSecret: testhelpers.TestJWTSecret}
	app := impersonateApp(handlers.NewAdminImpersonateHandler(db, cfg), "admin@x.com")
	require.Equal(t, fiber.StatusServiceUnavailable, impReq(t, app, "/imp/"+uuid.NewString()))
}

func TestImpersonate_TeamHasNoUsers(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	team := testhelpers.MustCreateTeamDB(t, db, "pro") // team row, zero users
	cfg := &config.Config{Environment: "test", JWTSecret: testhelpers.TestJWTSecret}
	app := impersonateApp(handlers.NewAdminImpersonateHandler(db, cfg), "admin@x.com")
	require.Equal(t, fiber.StatusConflict, impReq(t, app, "/imp/"+team))
}

func TestImpersonate_Success(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	team := testhelpers.MustCreateTeamDB(t, db, "pro")
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner')`,
		team, testhelpers.UniqueEmail(t))
	require.NoError(t, err)
	cfg := &config.Config{Environment: "test", JWTSecret: testhelpers.TestJWTSecret}
	app := impersonateApp(handlers.NewAdminImpersonateHandler(db, cfg), "admin@x.com")
	require.Equal(t, fiber.StatusOK, impReq(t, app, "/imp/"+team))
}
