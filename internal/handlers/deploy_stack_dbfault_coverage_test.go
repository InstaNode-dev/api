package handlers_test

// deploy_stack_dbfault_coverage_test.go — drives the 503 "fetch_failed" /
// "list_failed" / "team_lookup_failed" error branches in deploy.go + stack.go
// by handing the handler a *closed* DB handle. Every query then returns
// "sql: database is closed", which is the non-ErrNotFound error arm.
//
// Scope: deploy.go + stack.go ONLY. Skips cleanly when TEST_DATABASE_URL unset.

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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

// closedDBApp builds a fiber app whose deploy + stack handlers run against a
// CLOSED *sql.DB so every model query errors. A valid JWT still passes the
// auth middleware (it doesn't touch the DB), so the request reaches the
// handler and exercises the non-ErrNotFound error arm.
func closedDBApp(t *testing.T) (*fiber.App, *config.Config) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/instant_dev_test?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Close()) // closed on purpose

	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": e.Error()})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())

	app.Get("/deploy/:id", middleware.RequireAuth(cfg), dh.Get)
	app.Get("/api/v1/deployments", middleware.RequireAuth(cfg), dh.List)
	app.Patch("/deploy/:id/env", middleware.RequireAuth(cfg), dh.UpdateEnv)
	app.Get("/api/v1/stacks", middleware.RequireAuth(cfg), sh.List)
	app.Get("/stacks/:slug", middleware.OptionalAuth(cfg), sh.Get)
	return app, cfg
}

func dbFaultJWT(t *testing.T) string {
	t.Helper()
	return testhelpers.MustSignSessionJWT(t, uuid.NewString(), uuid.NewString(), "dbfault@example.com")
}

func dbFaultNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping db-fault coverage test")
	}
}

func TestDeployGet_DBClosed_Returns503(t *testing.T) {
	dbFaultNeedsDB(t)
	app, _ := closedDBApp(t)
	req := httptest.NewRequest(http.MethodGet, "/deploy/some-app", nil)
	req.Header.Set("Authorization", "Bearer "+dbFaultJWT(t))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestDeployList_DBClosed_Returns503(t *testing.T) {
	dbFaultNeedsDB(t)
	app, _ := closedDBApp(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	req.Header.Set("Authorization", "Bearer "+dbFaultJWT(t))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestDeployUpdateEnv_DBClosed_Returns503(t *testing.T) {
	dbFaultNeedsDB(t)
	app, _ := closedDBApp(t)
	req := httptest.NewRequest(http.MethodPatch, "/deploy/some-app/env",
		strings.NewReader(`{"env":{"FOO":"bar"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+dbFaultJWT(t))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestStackList_DBClosed_Returns503(t *testing.T) {
	dbFaultNeedsDB(t)
	app, _ := closedDBApp(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stacks", nil)
	req.Header.Set("Authorization", "Bearer "+dbFaultJWT(t))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestStackGet_DBClosed_Returns503(t *testing.T) {
	dbFaultNeedsDB(t)
	app, _ := closedDBApp(t)
	req := httptest.NewRequest(http.MethodGet, "/stacks/some-slug", nil)
	req.Header.Set("Authorization", "Bearer "+dbFaultJWT(t))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
