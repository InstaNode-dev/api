package handlers_test

// cli_auth_complete_test.go — D2 (2026-06-10): `instant login` was broken
// because nothing ever flipped a pending CLI session to complete
// (CompleteCLISession had zero callers). POST /auth/cli/:id/complete is that
// missing call site. These DB-backed integration tests drive the FULL flow
// against a real Postgres + Redis through the production router (NewTestApp):
//
//	POST /auth/cli                  → {session_id}
//	POST /auth/cli/{id}/complete    (session Bearer) → 200 {ok:true}
//	GET  /auth/cli/{id}             → 200 {status:"complete", api_token}
//
// plus the auth gate (no Bearer → 401) and the stale-session 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// createCLISession POSTs /auth/cli and returns the new session_id.
func createCLISession(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
},
) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/auth/cli", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "POST /auth/cli must return 201")
	var body struct {
		SessionID string `json:"session_id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	require.NotEmpty(t, body.SessionID, "session_id must be returned")
	return body.SessionID
}

// TestE2E_CLIDeviceFlow_Complete_FlipsSessionAndMintsToken is the happy-path
// integration test the route-coverage guard maps POST /auth/cli/:id/complete to.
// It mints a cohort-equivalent team + user, signs a session JWT, drives the
// device-flow create → complete → poll round-trip, and asserts the poll returns
// the canonical {status:"complete", api_token} shape with a real api key.
func TestE2E_CLIDeviceFlow_Complete_FlipsSessionAndMintsToken(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// A real team + user + session JWT (the user who approves the CLI login).
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	// 1. CLI creates a pending session.
	sessionID := createCLISession(t, app)

	// Before completion, the poll must report pending (202, status="pending").
	pollReq := httptest.NewRequest(http.MethodGet, "/auth/cli/"+sessionID, nil)
	pollResp, err := app.Test(pollReq, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusAccepted, pollResp.StatusCode, "pending poll must be 202")
	var pendingBody map[string]any
	require.NoError(t, json.NewDecoder(pollResp.Body).Decode(&pendingBody))
	pollResp.Body.Close()
	assert.Equal(t, "pending", pendingBody["status"], "pending poll must carry status=pending")
	_, hasToken := pendingBody["api_token"]
	assert.False(t, hasToken, "no api_token before completion")

	// 2. The signed-in user completes the session (authenticated POST).
	completeReq := httptest.NewRequest(http.MethodPost,
		"/auth/cli/"+sessionID+"/complete", nil)
	completeReq.Header.Set("Authorization", "Bearer "+sessionJWT)
	completeResp, err := app.Test(completeReq, 5000)
	require.NoError(t, err)
	defer completeResp.Body.Close()
	require.Equal(t, http.StatusOK, completeResp.StatusCode,
		"POST /auth/cli/:id/complete with a valid session must return 200")
	var completeBody map[string]any
	require.NoError(t, json.NewDecoder(completeResp.Body).Decode(&completeBody))
	assert.Equal(t, true, completeBody["ok"], "complete response must be {ok:true}")

	// 3. The CLI's next poll now returns the api_token (single-use, 200).
	poll2 := httptest.NewRequest(http.MethodGet, "/auth/cli/"+sessionID, nil)
	poll2Resp, err := app.Test(poll2, 5000)
	require.NoError(t, err)
	defer poll2Resp.Body.Close()
	require.Equal(t, http.StatusOK, poll2Resp.StatusCode, "completed poll must be 200")
	var done map[string]any
	require.NoError(t, json.NewDecoder(poll2Resp.Body).Decode(&done))

	assert.Equal(t, "complete", done["status"], "completed poll must carry status=complete (CONTRACT)")
	apiToken, _ := done["api_token"].(string)
	assert.NotEmpty(t, apiToken, "completed poll must return a non-empty api_token (CONTRACT)")
	assert.True(t, strings.HasPrefix(apiToken, "ink_"),
		"api_token must be a real PAT (ink_ prefix); got %q", apiToken)
	assert.Equal(t, "hobby", done["tier"], "completed poll echoes the team tier")
	assert.Equal(t, email, done["email"], "completed poll echoes the user email")

	// The minted key must actually exist in the team's api_keys table.
	var keyCount int
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM api_keys WHERE team_id = $1::uuid AND revoked_at IS NULL`,
		teamID).Scan(&keyCount))
	assert.GreaterOrEqual(t, keyCount, 1, "completion must persist a team API key")
}

// TestCLIDeviceFlow_Complete_RequiresAuth asserts the complete endpoint is
// session-gated: no Bearer → 401, never an unauthenticated session flip.
func TestCLIDeviceFlow_Complete_RequiresAuth(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	sessionID := createCLISession(t, app)

	req := httptest.NewRequest(http.MethodPost, "/auth/cli/"+sessionID+"/complete", nil)
	// No Authorization header.
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"complete without a session Bearer must be 401")
}

// TestCLIDeviceFlow_Complete_StaleSession_Returns404 asserts a complete against
// an unknown/expired session id 404s rather than minting a key for a session no
// CLI is polling.
func TestCLIDeviceFlow_Complete_StaleSession_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID, teamID, email)

	req := httptest.NewRequest(http.MethodPost,
		"/auth/cli/0000000000000000000000000000dead/complete", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"complete against an unknown session id must be 404")
}
