package handlers_test

// team_deletion_test.go — coverage for DELETE /api/v1/team +
// POST /api/v1/team/restore. Mirrors the resource_pause_test.go style:
// each test stands up its own DB + Redis + Fiber app, builds a team +
// user (with explicit role='owner' so RequireRole passes) + JWT,
// fires the request, asserts the response shape AND the row's status /
// deletion_requested_at columns.
//
// Scenarios covered:
//   1. Owner with matching slug → 202 + status=deletion_requested.
//   2. Member (not owner) → 403.
//   3. Owner with WRONG slug → 409 slug_mismatch, row unchanged.
//   4. Owner: paused resources side-effect.
//   5. Restore inside grace → 200, row back to active.
//   6. Restore after grace expired → 410.
//   7. Audit emit shape (kind + metadata keys).
//   8. Razorpay cancel FAILURE — handler ABORTS with 502, team left fully
//      active, a team.deletion_failed audit row records the aborted
//      attempt. "Stop the money" runs first and is a hard gate (atomic-
//      deletion hardening, 2026-05-19).
//   9. Razorpay-abort idempotency — re-running DELETE after an aborted
//      attempt behaves identically (502, still active).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// teamDelFixture wires up the common test setup: app, DB, owner user + JWT.
type teamDelFixture struct {
	app    teamDelApp
	db     *sql.DB
	teamID string
	userID string
	jwt    string
	slug   string
}

type teamDelApp interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}

func setupTeamDelFixture(t *testing.T, planTier, role string) teamDelFixture {
	t.Helper()

	db, _ := testhelpers.SetupTestDB(t)
	t.Cleanup(func() { db.Close() })
	rdb, _ := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { rdb.Close() })

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	t.Cleanup(cleanApp)

	teamID := testhelpers.MustCreateTeamDB(t, db, planTier)

	// Read back the team name so we know the slug to confirm with.
	var teamName sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT name FROM teams WHERE id = $1::uuid`, teamID,
	).Scan(&teamName))

	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
		teamID, email, role,
	).Scan(&userID))
	jwt := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	slug := ""
	if teamName.Valid {
		slug = teamName.String
	}

	return teamDelFixture{
		app:    app,
		db:     db,
		teamID: teamID,
		userID: userID,
		jwt:    jwt,
		slug:   slug,
	}
}

func doTeamDelete(t *testing.T, app teamDelApp, jwt, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/team",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func doTeamRestore(t *testing.T, app teamDelApp, jwt string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/team/restore", nil)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestTeamDelete_Owner_HappyPath — scenario 1.
func TestTeamDelete_Owner_HappyPath(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	body := `{"confirm_team_slug":"` + f.slug + `"}`
	resp := doTeamDelete(t, f.app, f.jwt, body)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "want 202")

	// Response body carries deletion_at + grace window.
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.Equal(t, float64(30), out["grace_window_days"])
	assert.NotEmpty(t, out["deletion_at"])
	assert.NotEmpty(t, out["how_to_cancel"])

	// DB row state — status flipped, deletion_requested_at set.
	var status string
	var reqAt sql.NullTime
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status, deletion_requested_at FROM teams WHERE id = $1::uuid`,
		f.teamID,
	).Scan(&status, &reqAt))
	assert.Equal(t, "deletion_requested", status)
	assert.True(t, reqAt.Valid, "deletion_requested_at must be set")
}

// TestTeamDelete_NotOwner_Forbidden — scenario 2.
// A 'member' role cannot call DELETE /api/v1/team.
func TestTeamDelete_NotOwner_Forbidden(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "member")

	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"`+f.slug+`"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "non-owner must be rejected")

	// Row unchanged.
	var status string
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status FROM teams WHERE id = $1::uuid`, f.teamID,
	).Scan(&status))
	assert.Equal(t, "active", status)
}

// TestTeamDelete_SlugMismatch_Conflict — scenario 3.
func TestTeamDelete_SlugMismatch_Conflict(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"definitely-wrong-slug"}`)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, "slug_mismatch", out["error"])
	assert.NotEmpty(t, out["agent_action"], "slug_mismatch must carry agent_action")

	// Row unchanged.
	var status string
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status FROM teams WHERE id = $1::uuid`, f.teamID,
	).Scan(&status))
	assert.Equal(t, "active", status)
}

// TestTeamDelete_PausesResources — scenario 4.
// Every active team-owned resource flips to status='paused' with paused_at set.
func TestTeamDelete_PausesResources(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	// Seed three active resources for the team.
	for i := 0; i < 3; i++ {
		_, err := f.db.ExecContext(context.Background(), `
			INSERT INTO resources (team_id, resource_type, tier, status)
			VALUES ($1::uuid, $2, 'pro', 'active')
		`, f.teamID, "postgres")
		require.NoError(t, err)
	}

	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"`+f.slug+`"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// All resources paused.
	var n int
	require.NoError(t, f.db.QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM resources
		WHERE team_id = $1::uuid AND status = 'paused' AND paused_at IS NOT NULL
	`, f.teamID).Scan(&n))
	assert.Equal(t, 3, n, "all 3 resources must be paused")
}

// TestTeamRestore_InsideGrace_Active — scenario 5.
func TestTeamRestore_InsideGrace_Active(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	// First, request deletion.
	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"`+f.slug+`"}`)
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Then restore.
	resp = doTeamRestore(t, f.app, f.jwt)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.Equal(t, true, out["ok"])
	assert.Equal(t, "active", out["status"])

	// Row back to active.
	var status string
	var reqAt sql.NullTime
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status, deletion_requested_at FROM teams WHERE id = $1::uuid`,
		f.teamID,
	).Scan(&status, &reqAt))
	assert.Equal(t, "active", status)
	assert.False(t, reqAt.Valid, "deletion_requested_at must be cleared")
}

// TestTeamRestore_AfterGrace_Gone — scenario 6.
// Backdate deletion_requested_at to >30d ago and try to restore — must 410.
func TestTeamRestore_AfterGrace_Gone(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	// Manually put the row into deletion_requested + backdate by 31 days.
	_, err := f.db.ExecContext(context.Background(), `
		UPDATE teams
		   SET status = 'deletion_requested',
		       deletion_requested_at = now() - interval '31 days'
		 WHERE id = $1::uuid
	`, f.teamID)
	require.NoError(t, err)

	resp := doTeamRestore(t, f.app, f.jwt)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)

	// Row still in deletion_requested (worker would tombstone next tick).
	var status string
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status FROM teams WHERE id = $1::uuid`, f.teamID,
	).Scan(&status))
	assert.Equal(t, "deletion_requested", status)
}

// TestTeamDelete_AuditEmitted — scenario 7.
// An audit_log row of kind team.deletion_requested must land with
// metadata carrying requested_by_user_id + confirm_slug_provided + razorpay_cancel_result.
func TestTeamDelete_AuditEmitted(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"`+f.slug+`"}`)
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	var kind string
	var metaStr sql.NullString
	require.NoError(t, f.db.QueryRowContext(context.Background(), `
		SELECT kind, metadata::text FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
		 ORDER BY created_at DESC LIMIT 1
	`, f.teamID, models.AuditKindTeamDeletionRequested,
	).Scan(&kind, &metaStr))
	assert.Equal(t, "team.deletion_requested", kind)
	require.True(t, metaStr.Valid)

	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaStr.String), &meta))
	assert.Equal(t, f.userID, meta["requested_by_user_id"])
	assert.Equal(t, f.slug, meta["confirm_slug_provided"])
	assert.Contains(t, []any{"ok", "skipped"}, meta["razorpay_cancel_result"],
		"razorpay_cancel_result should be 'ok' or 'skipped' (no live sub in test)")
}

// TestTeamDelete_RazorpayCancelFails_Aborts — atomic-deletion scenario (d).
//
// CONTRACT (changed 2026-05-19, atomic-deletion hardening): a Razorpay
// subscription-cancel failure ABORTS the whole deletion. "Stop the money"
// runs FIRST and is a hard gate — a team must never be marked for deletion
// while its card can still be charged. The previous behaviour (202 + best-
// effort) is replaced.
//
// This test asserts:
//   - the response is 502 (not 202),
//   - the team is left FULLY 'active' — no state change, no paused
//     resources,
//   - a team.deletion_failed audit row records the aborted attempt.
//
// We exercise the handler directly (skipping the test app's route
// registration) so we can inject failingCanceler without adding a new
// testhelpers seam.
func TestTeamDelete_RazorpayCancelFails_Aborts(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	h := handlers.NewTeamDeletionHandler(f.db, nil)
	h.CancelSubscription = failingCanceler{}

	resp := callTeamDeleteWithHandler(t, h, f.jwt,
		`{"confirm_team_slug":"`+f.slug+`"}`, f.teamID, f.userID)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"a Razorpay cancel failure must abort the deletion with 502")

	// The team must be left UNTOUCHED — still 'active', destruction not
	// initiated. This is the core safety property: no half-deletion.
	var status string
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status FROM teams WHERE id = $1::uuid`, f.teamID,
	).Scan(&status))
	assert.Equal(t, models.TeamStatusActive, status,
		"team must remain active after an aborted deletion")

	// A team.deletion_failed audit row records the aborted attempt so the
	// operator and the customer can see the cancel failed loudly.
	var metaStr sql.NullString
	require.NoError(t, f.db.QueryRowContext(context.Background(), `
		SELECT metadata::text FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
		 ORDER BY created_at DESC LIMIT 1
	`, f.teamID, models.AuditKindTeamDeletionFailed,
	).Scan(&metaStr))
	require.True(t, metaStr.Valid, "an aborted deletion must emit a team.deletion_failed audit row")

	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaStr.String), &meta))
	got, _ := meta["razorpay_cancel_result"].(string)
	assert.Contains(t, got, "failed:", "audit must record the failure cause")
	aborted, _ := meta["aborted"].(bool)
	assert.True(t, aborted, "audit metadata must flag the abort")
}

// TestTeamDelete_RazorpayCancelFails_Idempotent — atomic-deletion scenario.
// Re-running DELETE after an aborted attempt must behave identically (still
// 502, still active) — the abort path is itself idempotent because it makes
// no state change.
func TestTeamDelete_RazorpayCancelFails_Idempotent(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")
	h := handlers.NewTeamDeletionHandler(f.db, nil)
	h.CancelSubscription = failingCanceler{}

	for i := 0; i < 3; i++ {
		resp := callTeamDeleteWithHandler(t, h, f.jwt,
			`{"confirm_team_slug":"`+f.slug+`"}`, f.teamID, f.userID)
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode,
			"abort path must be idempotent across retries (attempt %d)", i+1)
		resp.Body.Close()
	}
	var status string
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT status FROM teams WHERE id = $1::uuid`, f.teamID).Scan(&status))
	assert.Equal(t, models.TeamStatusActive, status,
		"team still active after repeated aborted deletions")
}

// failingCanceler is a SubscriptionCanceler that always returns an error,
// used to exercise the best-effort cancel path.
type failingCanceler struct{}

func (failingCanceler) CancelForTeam(ctx context.Context, teamID uuid.UUID) error {
	return errors.New("simulated razorpay 503")
}

// Compile-time check that failingCanceler satisfies the contract.
var _ handlers.SubscriptionCanceler = failingCanceler{}

// callTeamDeleteWithHandler stands up a minimal Fiber app around a single
// TeamDeletionHandler instance so the test can inject the canceler
// directly. Middleware chain mirrors production (RequireAuth + RequireRole)
// but avoids re-registering the rest of the API.
func callTeamDeleteWithHandler(t *testing.T, h *handlers.TeamDeletionHandler, jwt, body, teamID, userID string) *http.Response {
	t.Helper()

	cfg := newTestConfigForDeletionHandler()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"ok": false, "error": "internal_error", "message": err.Error(),
			})
		},
	})
	api := app.Group("/api/v1",
		middleware.RequireAuth(cfg),
		middleware.PopulateTeamRole(),
	)
	api.Delete("/team", middleware.RequireRole("owner"), h.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/team",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	_ = teamID
	_ = userID
	return resp
}

// newTestConfigForDeletionHandler returns a minimal config with the same
// JWT secret testhelpers uses, so the JWT minted by MustSignSessionJWT
// still validates through RequireAuth.
func newTestConfigForDeletionHandler() *config.Config {
	return &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		EnabledServices: "redis",
	}
}

// TestTeamRestore_RemovesAuditAndResumesResources — supplementary check
// that the resume side-effect matches the brief: paused → active.
func TestTeamRestore_RemovesAuditAndResumesResources(t *testing.T) {
	f := setupTeamDelFixture(t, "pro", "owner")

	// Seed a resource + request deletion (which pauses it).
	_, err := f.db.ExecContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
	`, f.teamID)
	require.NoError(t, err)

	resp := doTeamDelete(t, f.app, f.jwt, `{"confirm_team_slug":"`+f.slug+`"}`)
	resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Verify paused.
	var paused int
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resources WHERE team_id = $1::uuid AND status = 'paused'`,
		f.teamID,
	).Scan(&paused))
	require.Equal(t, 1, paused)

	// Restore.
	resp = doTeamRestore(t, f.app, f.jwt)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify active again.
	var active int
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resources WHERE team_id = $1::uuid AND status = 'active'`,
		f.teamID,
	).Scan(&active))
	assert.Equal(t, 1, active)

	// Audit row of canceled kind exists.
	var n int
	require.NoError(t, f.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE team_id = $1::uuid AND kind = $2`,
		f.teamID, models.AuditKindTeamDeletionCanceled,
	).Scan(&n))
	assert.Equal(t, 1, n)
}
