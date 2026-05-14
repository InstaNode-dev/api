package handlers_test

// deploy_delete_test.go — coverage for Wave FIX-I's two-step deletion
// flow on DELETE /api/v1/deployments/:id.
//
// Four happy / sad paths exercised end-to-end via the test fiber app:
//
//   1. paid team + email wired → 202 pending_confirmation envelope,
//      pending_deletions row lands, deployment row still alive.
//   2. paid team → POST /confirm-deletion?token=<plaintext> → 200
//      deletion_status=confirmed; pending row flips to 'confirmed',
//      deployment row hard-deleted.
//   3. paid team → DELETE /confirm-deletion → 200 deletion_status=
//      cancelled; pending row flips to 'cancelled', deployment row
//      still alive.
//   4. expired token → 410 deletion_token_invalid (the lookup gates on
//      expires_at > now()).

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// seedFixITeamUserAndDeploy inserts a (team, owner user, deployment)
// triple against the supplied DB and returns the IDs + session JWT.
// Kept inline-friendly so each test owns its own cleanup window.
func seedFixITeamUserAndDeploy(t *testing.T, db *sql.DB, tier, email string) (teamID, userID, deploymentID uuid.UUID, appID, sessionJWT string) {
	t.Helper()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, tier)
	teamID = uuid.MustParse(teamIDStr)
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO users (team_id, email, role, is_primary)
		VALUES ($1, $2, 'owner', true)
		RETURNING id
	`, teamID, email).Scan(&userID))

	appID = "fixi-" + uuid.NewString()[:8]
	d, err := models.CreateDeployment(context.Background(), db, models.CreateDeploymentParams{
		TeamID: teamID,
		AppID:  appID,
		Tier:   tier,
	})
	require.NoError(t, err)
	deploymentID = d.ID

	sessionJWT = testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, email)
	return
}

// TestDeployDelete_PaidTeam_QueuesPendingConfirmation — path 1.
func TestDeployDelete_PaidTeam_QueuesPendingConfirmation(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID, _, deploymentID, appID, sessionJWT := seedFixITeamUserAndDeploy(t, db, "pro", "owner-fixi-1@example.com")
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM pending_deletions WHERE resource_id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"paid-tier DELETE must return 202 (pending confirmation)")

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "pending_confirmation", got["deletion_status"])
	masked, _ := got["confirmation_sent_to"].(string)
	assert.Contains(t, masked, "***@example.com",
		"confirmation_sent_to must be masked")
	assert.NotEmpty(t, got["agent_action"], "agent_action sentence required")

	// Pending row landed.
	var pendingStatus string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM pending_deletions WHERE resource_id = $1 AND resource_type = 'deploy'`,
		deploymentID).Scan(&pendingStatus))
	assert.Equal(t, "pending", pendingStatus)

	// Deployment row still alive (slot still consumed).
	var stillThere bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM deployments WHERE id = $1)`, deploymentID).Scan(&stillThere))
	assert.True(t, stillThere, "deployment row must still exist before confirmation")
}

// TestDeployDelete_PaidTeam_HeaderBypass — path 1b. The
// X-Skip-Email-Confirmation header short-circuits the email flow.
func TestDeployDelete_PaidTeam_HeaderBypass(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID, _, deploymentID, appID, sessionJWT := seedFixITeamUserAndDeploy(t, db, "pro", "owner-fixi-bypass@example.com")
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.2")
	req.Header.Set("X-Skip-Email-Confirmation", "yes")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"header bypass must return 200 (immediate destruction)")

	var stillThere bool
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM deployments WHERE id = $1)`, deploymentID).Scan(&stillThere))
	assert.False(t, stillThere, "deployment row must be hard-deleted on bypass")
}

// TestDeployDelete_ConfirmFlow — path 2.
func TestDeployDelete_ConfirmFlow(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID, userID, deploymentID, appID, sessionJWT := seedFixITeamUserAndDeploy(t, db, "pro", "owner-fixi-2@example.com")
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Insert the pending row directly so we can capture the plaintext
	// token — the email-handler path returns it via the email body
	// only, which we don't intercept in tests.
	ctx := context.Background()
	pending, plaintext, err := models.CreatePendingDeletion(ctx, db, deploymentID,
		models.PendingDeletionResourceDeploy, teamID, userID,
		"owner-fixi-2@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+appID+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "confirmed", got["deletion_status"])

	// Pending row flipped.
	var pendingStatus string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT status FROM pending_deletions WHERE id = $1`, pending.ID).Scan(&pendingStatus))
	assert.Equal(t, "confirmed", pendingStatus)

	// Deployment row gone.
	var stillThere bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM deployments WHERE id = $1)`, deploymentID).Scan(&stillThere))
	assert.False(t, stillThere)
}

// TestDeployDelete_CancelFlow — path 3.
func TestDeployDelete_CancelFlow(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID, userID, deploymentID, appID, sessionJWT := seedFixITeamUserAndDeploy(t, db, "pro", "owner-fixi-3@example.com")
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	pending, _, err := models.CreatePendingDeletion(ctx, db, deploymentID,
		models.PendingDeletionResourceDeploy, teamID, userID,
		"owner-fixi-3@example.com", 15*time.Minute)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/deployments/"+appID+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
	assert.Equal(t, "cancelled", got["deletion_status"])

	// Pending row cancelled.
	var pendingStatus string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT status FROM pending_deletions WHERE id = $1`, pending.ID).Scan(&pendingStatus))
	assert.Equal(t, "cancelled", pendingStatus)

	// Deployment still alive.
	var stillThere bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM deployments WHERE id = $1)`, deploymentID).Scan(&stillThere))
	assert.True(t, stillThere)
}

// TestDeployDelete_ConfirmExpiredToken — path 4.
func TestDeployDelete_ConfirmExpiredToken(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID, userID, deploymentID, appID, sessionJWT := seedFixITeamUserAndDeploy(t, db, "pro", "owner-fixi-4@example.com")
	defer db.Exec(`DELETE FROM deployments WHERE id = $1`, deploymentID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	ctx := context.Background()
	pending, plaintext, err := models.CreatePendingDeletion(ctx, db, deploymentID,
		models.PendingDeletionResourceDeploy, teamID, userID,
		"owner-fixi-4@example.com", 1*time.Millisecond)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM pending_deletions WHERE id = $1`, pending.ID)
	time.Sleep(20 * time.Millisecond)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+appID+"/confirm-deletion?token="+plaintext, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusGone, resp.StatusCode,
		"expired token must return 410 Gone")
	body, _ := io.ReadAll(resp.Body)
	assert.True(t, strings.Contains(string(body), "deletion_token_invalid"),
		"envelope must surface the deletion_token_invalid code; got %s", body)
}
