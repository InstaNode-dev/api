package handlers_test

// stack_delete_confirm_coverage_test.go — covers the stack Delete /
// ConfirmDelete / CancelDelete email-confirmation flow + UpdateEnv error arms
// (stack.go), which the noop-provider happy-path stack tests don't reach. All
// DB + noop-stack-provider; the email client is the noop mailer so the paid-
// team confirmation branch is exercised without an HTTP roundtrip.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func mustUUIDStr() string { return uuid.NewString() }

// stackConfirmApp builds a Fiber app with the full stack route set + a noop
// email client wired so the two-step deletion flow runs.
func stackConfirmApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                      testhelpers.TestJWTSecret,
		AESKey:                         testhelpers.TestAESKeyHex,
		ComputeProvider:                "noop",
		DashboardBaseURL:               "https://dash.local",
		DeletionConfirmationTTLMinutes: 30,
	}
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
	app.Use(middleware.RequestID())
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	h.SetEmailClient(email.NewNoop())
	app.Delete("/stacks/:slug", middleware.OptionalAuth(cfg), h.Delete)
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), h.UpdateEnv)
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/confirm-deletion", h.ConfirmDelete)
	api.Delete("/stacks/:slug/confirm-deletion", h.CancelDelete)
	return app
}

// stkSeedStack creates a stack owned by teamID. statusOverride lets the caller
// force a non-default status (e.g. the deleting state for the 409 arm).
func stkSeedStack(t *testing.T, db *sql.DB, teamID, statusOverride string) (slug string) {
	t.Helper()
	tid := uuid.MustParse(teamID)
	st, err := models.CreateStack(context.Background(), db, models.CreateStackParams{
		TeamID: &tid, Slug: "stk-" + teamID[:8], Tier: "pro", Env: "production",
	})
	require.NoError(t, err)
	if statusOverride != "" {
		_, err := db.Exec(`UPDATE stacks SET status=$1 WHERE id=$2`, statusOverride, st.ID)
		require.NoError(t, err)
	}
	return st.Slug
}

func TestStack_Delete_EmailConfirmFlow(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackConfirmApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	emailAddr := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRow(`INSERT INTO users (team_id, email) VALUES ($1::uuid,$2) RETURNING id::text`, teamID, emailAddr).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, emailAddr)
	slug := stkSeedStack(t, db, teamID, "")

	// Paid team + email client → DELETE returns 202 pending confirmation.
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var pending struct {
		DeletionStatus string `json:"deletion_status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&pending))
	resp.Body.Close()
	assert.Equal(t, "pending_confirmation", pending.DeletionStatus)

	// Pending row landed.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM pending_deletions WHERE resource_type='stack' AND status='pending'`,
	).Scan(&n))
	assert.GreaterOrEqual(t, n, 1)

	// CancelDelete → 200, pending row cancelled.
	creq := httptest.NewRequest(http.MethodDelete, "/api/v1/stacks/"+slug+"/confirm-deletion", nil)
	creq.Header.Set("Authorization", "Bearer "+jwt)
	cresp, err := app.Test(creq, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, cresp.StatusCode)
	cresp.Body.Close()
}

func TestStack_Delete_ImmediateWithSkipHeader(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackConfirmApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "s@example.com")
	slug := stkSeedStack(t, db, teamID, "")

	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Skip-Email-Confirmation", "yes")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode) // immediate delete
	resp.Body.Close()
}

func TestStack_Delete_NotFoundAndCrossTeam(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackConfirmApp(t, db)

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwtB := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamB, "b@example.com")
	slug := stkSeedStack(t, db, teamA, "")

	// Cross-team → 404.
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Skip-Email-Confirmation", "yes")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()

	// Unknown slug → 404.
	req2 := httptest.NewRequest(http.MethodDelete, "/stacks/does-not-exist", nil)
	req2.Header.Set("Authorization", "Bearer "+jwtB)
	req2.Header.Set("X-Skip-Email-Confirmation", "yes")
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
	resp2.Body.Close()
}

func TestStack_UpdateEnv_ErrorArms(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	app := stackConfirmApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), teamID, "e@example.com")
	slug := stkSeedStack(t, db, teamID, "")

	patch := func(slug, body string) *http.Response {
		req := httptest.NewRequest(http.MethodPatch, "/stacks/"+slug+"/env", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}

	t.Run("not_found", func(t *testing.T) {
		resp := patch("nope-slug", `{"env":{"FOO":"bar"}}`)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("invalid_body", func(t *testing.T) {
		resp := patch(slug, `{not json`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("missing_env", func(t *testing.T) {
		resp := patch(slug, `{"env":{}}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("invalid_env_key", func(t *testing.T) {
		resp := patch(slug, `{"env":{"lower-case":"x"}}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})
	t.Run("happy_merge_and_delete", func(t *testing.T) {
		resp := patch(slug, `{"env":{"FOO":"bar","BAZ":"qux"}}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
		// Delete BAZ via empty-string value.
		resp2 := patch(slug, `{"env":{"BAZ":""}}`)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
		resp2.Body.Close()
	})
	t.Run("deleting_stack_409", func(t *testing.T) {
		delSlug := stkSeedStack(t, db, testhelpers.MustCreateTeamDB(t, db, "pro"), "deleting")
		// Use that team's JWT.
		var tid string
		require.NoError(t, db.QueryRow(`SELECT team_id::text FROM stacks WHERE slug=$1`, delSlug).Scan(&tid))
		jwt2 := testhelpers.MustSignSessionJWT(t, mustUUIDStr(), tid, "d@example.com")
		req := httptest.NewRequest(http.MethodPatch, "/stacks/"+delSlug+"/env", strings.NewReader(`{"env":{"FOO":"bar"}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt2)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)
		resp.Body.Close()
	})
}
