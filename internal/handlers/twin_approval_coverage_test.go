package handlers_test

// twin_approval_coverage_test.go — covers the email-link approval gate of the
// provision-twin handler (twin.go beginTwinApproval / consumeApprovedTwin).
// The approval path returns 202 BEFORE any real provisioning, so it is fully
// hermetic — unlike the twin happy path (which provisions a real DB and skips
// under CI when the backend is unavailable). These were the two 0%-under-CI
// functions in twin.go.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestTwin_ApprovalGate_NonDevEnv_Returns202Pending(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	// Non-dev env, no approval_id → email-link approval gate fires → 202.
	resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging"})
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	var body struct {
		OK         bool   `json:"ok"`
		Status     string `json:"status"`
		ApprovalID string `json:"approval_id"`
		From       string `json:"from"`
		To         string `json:"to"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	resp.Body.Close()
	assert.True(t, body.OK)
	assert.Equal(t, "pending_approval", body.Status)
	assert.Equal(t, "production", body.From)
	assert.Equal(t, "staging", body.To)
	require.NotEmpty(t, body.ApprovalID)

	// A promote_approvals row landed for this team.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM promote_approvals WHERE id=$1::uuid AND team_id=$2::uuid`,
		body.ApprovalID, teamID,
	).Scan(&n))
	assert.Equal(t, 1, n)
}

func TestTwin_ApprovalConsume_Arms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := twinJWT(t, db, teamID)
	_, sourceToken := seedTwinSource(t, db, teamID, "postgres", "pro")

	t.Run("invalid_approval_id", func(t *testing.T) {
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": "not-a-uuid"})
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("approval_not_found", func(t *testing.T) {
		resp := postTwin(t, app, sourceToken, jwt, map[string]any{"env": "staging", "approval_id": uuid.NewString()})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}
