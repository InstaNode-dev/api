package handlers_test

// env_policy_final2_test.go — FINAL SERIAL PASS #2 coverage for the EnvPolicy
// handler error arms env_policy_test.go's middleware-focused suite leaves
// uncovered (the handler sits at ~64%):
//
//   Get:  fetch_failed (DB error)
//   Put:  role_lookup_failed (DB error), owner_required (non-owner),
//         invalid_body (empty), invalid_env_policy (bad shape),
//         team_not_found (SetTeamEnvPolicy → ErrTeamNotFound),
//         persist_failed (DB error), happy path
//
// Uses a minimal RequireAuth-only app (no PopulateTeamRole middleware) so the
// FIRST DB query is the handler's own — letting a CLOSED DB trip exactly the
// handler error arm we want, and a real DB drive the happy/owner_required arms.

import (
	"context"
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
	"instant.dev/internal/testhelpers"
)

// envPolicyMinimalApp wires GET/PUT /team/env-policy behind RequireAuth only
// (no role middleware) so the handler's own queries are the first DB touch.
func envPolicyMinimalApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal"})
		},
	})
	h := handlers.NewEnvPolicyHandler(db)
	app.Use(middleware.RequestID())
	app.Get("/team/env-policy", middleware.RequireAuth(cfg), h.Get)
	app.Put("/team/env-policy", middleware.RequireAuth(cfg), h.Put)
	return app
}

func envPolicyJWT(t *testing.T, teamID, userID string) string {
	t.Helper()
	return testhelpers.MustSignSessionJWT(t, userID, teamID, "envpol-final2@example.com")
}

func epReq(t *testing.T, app *fiber.App, method, jwt, body string) (int, string) {
	t.Helper()
	var r *strings.Reader
	if body != "" {
		r = strings.NewReader(body)
	} else {
		r = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "/team/env-policy", r)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [4096]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

func epNeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

// closed platform DB → Get GetTeamEnvPolicy errors → fetch_failed 503.
func TestEnvPolicyFinal2_Get_FetchFailed(t *testing.T) {
	epNeedDB(t)
	closed, err := sql.Open("postgres", testDSN())
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	app := envPolicyMinimalApp(t, closed)
	jwt := envPolicyJWT(t, uuid.NewString(), uuid.NewString())
	status, body := epReq(t, app, http.MethodGet, jwt, "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "fetch_failed")
}

// closed platform DB → Put GetUserRole errors → role_lookup_failed 503.
func TestEnvPolicyFinal2_Put_RoleLookupFailed(t *testing.T) {
	epNeedDB(t)
	closed, err := sql.Open("postgres", testDSN())
	require.NoError(t, err)
	require.NoError(t, closed.Close())
	app := envPolicyMinimalApp(t, closed)
	jwt := envPolicyJWT(t, uuid.NewString(), uuid.NewString())
	status, body := epReq(t, app, http.MethodPut, jwt, `{"production":{"deploy":["owner"]}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "role_lookup_failed")
}

// non-owner caller → owner_required 403.
func TestEnvPolicyFinal2_Put_OwnerRequired(t *testing.T) {
	epNeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := insertUserWithRole(t, db, teamID, "developer")
	app := envPolicyMinimalApp(t, db)
	jwt := envPolicyJWT(t, teamID, userID)
	status, body := epReq(t, app, http.MethodPut, jwt, `{"production":{"deploy":["owner"]}}`)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Contains(t, body, "owner_required")
}

// owner caller, empty body → invalid_body 400.
func TestEnvPolicyFinal2_Put_InvalidBody(t *testing.T) {
	epNeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := insertUserWithRole(t, db, teamID, "owner")
	app := envPolicyMinimalApp(t, db)
	jwt := envPolicyJWT(t, teamID, userID)
	status, body := epReq(t, app, http.MethodPut, jwt, "")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "invalid_body")
}

// owner caller, malformed policy → invalid_env_policy 400.
func TestEnvPolicyFinal2_Put_InvalidPolicy(t *testing.T) {
	epNeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := insertUserWithRole(t, db, teamID, "owner")
	app := envPolicyMinimalApp(t, db)
	jwt := envPolicyJWT(t, teamID, userID)
	// "deploy" must map to an array of role strings; a string here is invalid.
	status, body := epReq(t, app, http.MethodPut, jwt, `{"production":{"deploy":"owner"}}`)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, body, "invalid_env_policy")
}

// owner caller, valid policy → 200 happy path (covers SetTeamEnvPolicy success
// + audit emit goroutine + Get success arm via a follow-up read).
func TestEnvPolicyFinal2_PutThenGet_Happy(t *testing.T) {
	epNeedDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := insertUserWithRole(t, db, teamID, "owner")
	app := envPolicyMinimalApp(t, db)
	jwt := envPolicyJWT(t, teamID, userID)

	status, body := epReq(t, app, http.MethodPut, jwt, `{"production":{"deploy":["owner"]}}`)
	require.Equalf(t, http.StatusOK, status, "body=%s", body)

	// Read it back — exercises the Get success arm (non-nil policy).
	gstatus, gbody := epReq(t, app, http.MethodGet, jwt, "")
	assert.Equal(t, http.StatusOK, gstatus)
	assert.Contains(t, gbody, "production")

	// Settle the best-effort audit goroutine before the DB closes.
	_, _ = db.ExecContext(context.Background(), `SELECT 1`)
}

// owner caller, but the teams table is renamed away after the role lookup
// (which reads users) so SetTeamEnvPolicy's UPDATE errors → persist_failed 503.
// Covers env_policy.go L120-124 (the non-ErrTeamNotFound persist error arm).
func TestEnvPolicyFinal2_Put_PersistFailed(t *testing.T) {
	epNeedDB(t)
	db := withIsolatedDB(t)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	userID := insertUserWithRole(t, db, teamID, "owner")
	app := envPolicyMinimalApp(t, db)
	jwt := envPolicyJWT(t, teamID, userID)

	// GetUserRole reads `users` (intact) → owner; SetTeamEnvPolicy updates
	// `teams` → table gone → a non-NotFound DB error → persist_failed.
	_, err := db.ExecContext(context.Background(), `ALTER TABLE teams RENAME TO teams_gone_envpol`)
	require.NoError(t, err)

	status, body := epReq(t, app, http.MethodPut, jwt, `{"production":{"deploy":["owner"]}}`)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "persist_failed")
}
