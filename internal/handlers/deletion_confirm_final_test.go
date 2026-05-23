package handlers_test

// deletion_confirm_final_test.go — FINAL coverage pass for deletion_confirm.go's
// resolveEmailConfirmedDeletion DB-error arms (lookup_failed / mark_failed),
// driven through the stack ConfirmDelete route on a faultdb. The pending row +
// plaintext token are seeded on the pooled DB; the handler runs on a faultdb
// sharing the same postgres so the early team lookup succeeds and the targeted
// query errors.

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func dcConfirmApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:                      testhelpers.TestJWTSecret,
		AESKey:                         testhelpers.TestAESKeyHex,
		ComputeProvider:                "noop",
		DashboardBaseURL:               "https://dash.local",
		DeletionConfirmationTTLMinutes: 30,
	}
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
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	h.SetEmailClient(email.NewNoop())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/stacks/:slug/confirm-deletion", h.ConfirmDelete)
	return app
}

// missing token query param → missing_token (deletion_confirm.go:274).
func TestDeletionConfirmFinal_MissingToken_400(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, db)
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := whJWT(t, db, teamID)
	slug := stkSeedStack(t, db, teamID, "")

	app := dcConfirmApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stacks/"+slug+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// GetPendingDeletionByTokenHash errors → deletion_lookup_failed
// (deletion_confirm.go:286). requireStackTeam team-lookup(1) succeeds, the
// pending-deletion lookup(2) errors. failAfter=1.
func TestDeletionConfirmFinal_LookupError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)
	slug := stkSeedStack(t, seedDB, teamID, "")

	// Seed a pending-deletion row + token so a valid token is supplied (the
	// lookup itself errors via the fault driver, not a not-found).
	_, plaintext := dcSeedPendingDeletion(t, seedDB, teamID, slug)

	faultDB := openFaultDB(t, 1)
	app := dcConfirmApp(t, faultDB)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/stacks/"+slug+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// MarkPendingDeletionConfirmed errors → deletion_mark_failed
// (deletion_confirm.go:304). team(1) + pending-lookup(2) succeed, the CAS
// UPDATE(3) errors. failAfter=2.
func TestDeletionConfirmFinal_MarkError_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ensureStackTables(t, seedDB)
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "pro")
	jwt := whJWT(t, seedDB, teamID)
	slug := stkSeedStack(t, seedDB, teamID, "")
	_, plaintext := dcSeedPendingDeletion(t, seedDB, teamID, slug)

	faultDB := openFaultDB(t, 2)
	app := dcConfirmApp(t, faultDB)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/stacks/"+slug+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// dcSeedPendingDeletion creates a pending_deletions row for the stack and
// returns (pendingID, plaintextToken).
func dcSeedPendingDeletion(t *testing.T, db *sql.DB, teamID, slug string) (string, string) {
	t.Helper()
	stack, err := models.GetStackBySlug(context.Background(), db, slug)
	require.NoError(t, err)
	emailAddr := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, emailAddr).Scan(&userID))
	pending, plaintext, err := models.CreatePendingDeletion(
		context.Background(), db, stack.ID, models.PendingDeletionResourceStack,
		uuid.MustParse(teamID), uuid.MustParse(userID), emailAddr, 30*time.Minute)
	require.NoError(t, err)
	return pending.ID.String(), plaintext
}
