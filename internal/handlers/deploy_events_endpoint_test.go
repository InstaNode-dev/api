package handlers_test

// deploy_events_endpoint_test.go — coverage for GET /api/v1/deployments/:id/events.
//
// Triggering incident (swarm 2026-05-30): the silent-deploy-failure bug class
// left users with no read surface for the deployment_events autopsy rows the
// worker writes. This endpoint closes that gap. Tests pin:
//
//   - happy path: 3 events for a deployment, response is sorted DESC by
//     created_at, count + deployment_id + envelope shape match the contract
//   - empty timeline: a healthy deployment with zero events returns
//     {ok, events:[], count:0}
//   - cross-team RBAC: a deployment owned by another team returns 404 (NOT
//     403); the platform must never confirm the existence of deployments
//     owned by another team
//   - unknown id: 404 with the canonical envelope
//   - limit clamp: ?limit=500 returns at most 200 rows
//   - unauthenticated request: 401
//   - invalid limit: falls back to default 50
//
// All tests use the live Fiber test app + a real Postgres test DB so the
// HTTP envelope, route resolution, JWT middleware, and model SQL path are
// exercised end-to-end against the same SQL the production handler issues.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// deployEventsResponse mirrors the handler's response shape so the assertions
// can read typed fields instead of poking into map[string]any.
type deployEventsResponse struct {
	OK           bool   `json:"ok"`
	DeploymentID string `json:"deployment_id"`
	Events       []struct {
		Kind      string   `json:"kind"`
		Reason    string   `json:"reason"`
		ExitCode  *int     `json:"exit_code"`
		Event     string   `json:"event"`
		LastLines []string `json:"last_lines"`
		Hint      string   `json:"hint"`
		CreatedAt string   `json:"created_at"`
	} `json:"events"`
	Count int `json:"count"`
}

// TestDeployEvents_HappyPath_OrderingAndShape: 3 events seeded with varied
// timestamps; the handler must return them DESC by created_at and the JSON
// envelope must match the contract (ok / deployment_id / events / count).
func TestDeployEvents_HappyPath_OrderingAndShape(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "11111111-1111-1111-1111-111111111111", teamID, "events-happy@example.com")

	depID := uuid.New()
	appID := "evh" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'failed')
	`, depID, teamID, appID)
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	// Mix kinds: the partial unique index on (deployment_id, kind) WHERE
	// kind='failure_autopsy' allows only ONE failure_autopsy row per
	// deployment. Use 'lifecycle' for the older two and 'failure_autopsy'
	// for the most recent so the test exercises both kind label values.
	events := []struct {
		kind     string
		reason   string
		exit     any
		event    string
		atOffset time.Duration
	}{
		{"lifecycle", "image_pull_failed", nil, "ErrImagePull", -10 * time.Minute},
		{"lifecycle", "kaniko_oom", 137, "OOMKilled", -5 * time.Minute},
		{"failure_autopsy", "CrashLoopBackOff", 1, "CrashLoopBackOff", -1 * time.Minute},
	}
	for _, e := range events {
		_, err := db.Exec(`
			INSERT INTO deployment_events
				(deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		`, depID, e.kind, e.reason, e.exit, e.event, `["log-line-a","log-line-b"]`,
			"hint for "+e.reason, now.Add(e.atOffset))
		require.NoError(t, err)
	}

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body deployEventsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.True(t, body.OK)
	assert.Equal(t, depID.String(), body.DeploymentID, "deployment_id must echo the canonical UUID")
	assert.Equal(t, 3, body.Count)
	require.Len(t, body.Events, 3)

	// DESC by created_at — newest first.
	assert.Equal(t, "CrashLoopBackOff", body.Events[0].Reason, "newest first")
	assert.Equal(t, "kaniko_oom", body.Events[1].Reason)
	assert.Equal(t, "image_pull_failed", body.Events[2].Reason)

	// Per-row contract shape.
	assert.Equal(t, "failure_autopsy", body.Events[0].Kind, "most-recent row was inserted as failure_autopsy")
	assert.Equal(t, "lifecycle", body.Events[1].Kind, "middle row was inserted as lifecycle")
	require.NotNil(t, body.Events[0].ExitCode)
	assert.Equal(t, 1, *body.Events[0].ExitCode)
	assert.Equal(t, []string{"log-line-a", "log-line-b"}, body.Events[0].LastLines)
	assert.Equal(t, "CrashLoopBackOff", body.Events[0].Event)
	assert.Equal(t, "hint for CrashLoopBackOff", body.Events[0].Hint)
	assert.NotEmpty(t, body.Events[0].CreatedAt)

	// Null exit_code surfaces as JSON null (the *int is nil after decode).
	assert.Nil(t, body.Events[2].ExitCode, "image_pull_failed has no exit code → null in JSON")
}

// TestDeployEvents_Empty_ReturnsZeroCountWithEmptyArray: a deployment with no
// events must return an empty array (NOT null) and count:0 so consumers can
// `.events.length` without a nil check.
func TestDeployEvents_Empty_ReturnsZeroCountWithEmptyArray(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "22222222-2222-2222-2222-222222222222", teamID, "events-empty@example.com")

	depID := uuid.New()
	appID := "eve" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'healthy')
	`, depID, teamID, appID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read raw bytes so we can assert events is `[]` (not null / missing).
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"events":[]`, "events must be empty array, not null")
	assert.Contains(t, string(raw), `"count":0`)

	var body deployEventsResponse
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.True(t, body.OK)
	assert.Equal(t, 0, body.Count)
	assert.NotNil(t, body.Events)
	assert.Len(t, body.Events, 0)
}

// TestDeployEvents_CrossTeam_Returns404: a deployment owned by team A must
// NOT be visible to a signed-in user on team B. The platform returns 404 (NOT
// 403) so existence of cross-team deployments is never confirmed.
func TestDeployEvents_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Caller is in team B.
	sessionJWT := testhelpers.MustSignSessionJWT(t, "33333333-3333-3333-3333-333333333333", teamB, "events-crossteam@example.com")

	// Deployment belongs to team A.
	depID := uuid.New()
	appID := "evc" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'failed')
	`, depID, teamA, appID)
	require.NoError(t, err)
	// Seed an autopsy row so the test would NOT be vacuously 404.
	_, err = db.Exec(`
		INSERT INTO deployment_events
			(deployment_id, kind, reason, exit_code, event, last_lines, hint)
		VALUES ($1, 'failure_autopsy', 'kaniko_oom', 137, 'OOMKilled', '[]', 'hint')
	`, depID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team must return 404, NOT 403 (do not confirm existence)")

	var envelope struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.False(t, envelope.OK)
	assert.Equal(t, "not_found", envelope.Error)
}

// TestDeployEvents_UnknownID_Returns404: 404 with the canonical envelope when
// the :id slug doesn't match any deployment.
func TestDeployEvents_UnknownID_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "44444444-4444-4444-4444-444444444444", teamID, "events-unknown@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/never-existed-slug/events", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)

	var envelope struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&envelope))
	assert.False(t, envelope.OK)
	assert.Equal(t, "not_found", envelope.Error)
}

// TestDeployEvents_LimitClamp_AboveMaxReturnsAtMost200: ?limit=500 must clamp
// to the documented max (200). Seeds 205 events and asserts the response
// length is exactly 200.
func TestDeployEvents_LimitClamp_AboveMaxReturnsAtMost200(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "55555555-5555-5555-5555-555555555555", teamID, "events-limit@example.com")

	depID := uuid.New()
	appID := "evl" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'failed')
	`, depID, teamID, appID)
	require.NoError(t, err)

	// Seed 205 events so a request for ?limit=500 is forced to clamp to 200.
	base := time.Now().UTC().Add(-1 * time.Hour)
	for i := 0; i < 205; i++ {
		// 'lifecycle' kind: the failure_autopsy partial unique index only
		// allows one row per deployment with kind='failure_autopsy', so the
		// bulk inserts use the open-ended 'lifecycle' kind.
		_, err := db.Exec(`
			INSERT INTO deployment_events
				(deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
			VALUES ($1, 'lifecycle', $2, NULL, '', '[]', '', $3)
		`, depID, fmt.Sprintf("reason-%d", i), base.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
	}

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events?limit=500", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.5")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body deployEventsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 200, body.Count, "limit must clamp to documented max (200)")
	assert.Len(t, body.Events, 200)
}

// TestDeployEvents_Unauthenticated_Returns401: an unauthenticated request must
// be rejected at the middleware boundary before any DB lookup.
func TestDeployEvents_Unauthenticated_Returns401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/anyslug/events", nil)
	req.Header.Set("X-Forwarded-For", "10.99.0.6")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestDeployEvents_InvalidLimit_FallsBackToDefault: a non-integer / negative
// ?limit= silently falls back to the default (50). Seeds 60 rows so a "broken"
// limit still returns the default page size.
func TestDeployEvents_InvalidLimit_FallsBackToDefault(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, "66666666-6666-6666-6666-666666666666", teamID, "events-invlim@example.com")

	depID := uuid.New()
	appID := "evi" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'failed')
	`, depID, teamID, appID)
	require.NoError(t, err)
	base := time.Now().UTC().Add(-1 * time.Hour)
	for i := 0; i < 60; i++ {
		// 'lifecycle' kind: the failure_autopsy partial unique index only
		// allows one row per deployment with kind='failure_autopsy', so the
		// bulk inserts use the open-ended 'lifecycle' kind.
		_, err := db.Exec(`
			INSERT INTO deployment_events
				(deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
			VALUES ($1, 'lifecycle', $2, NULL, '', '[]', '', $3)
		`, depID, fmt.Sprintf("reason-%d", i), base.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
	}

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Non-integer ?limit should fall through to the default (50), not 500.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events?limit=not-a-number", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.99.0.7")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body deployEventsResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 50, body.Count, "invalid limit must fall back to default (50)")
	assert.Len(t, body.Events, 50)
}
