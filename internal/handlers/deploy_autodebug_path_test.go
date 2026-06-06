package handlers_test

// deploy_autodebug_path_test.go — the end-to-end AUTO-DEBUG PATH integration
// test for a FAILED deployment (task #70, docs/ci/02-FAILURE-DIAGNOSIS-AND-
// AUTODEBUG.md §5.1).
//
// The pieces of the failure-diagnosis surface are each unit/integration-tested
// elsewhere (deploy_events_endpoint_test.go: ordering/empty/clamp/cross-team;
// deploy_buildfailed_autopsy_test.go: the autopsy "failure" field on GET
// /deploy/:id). This file asserts them as ONE coherent contract — the exact
// loop an MCP agent or the dashboard FailureAutopsyPanel runs to diagnose a
// failed deploy WITHOUT cluster access:
//
//   1. GET /api/v1/deployments/:id        → status="failed" + non-empty
//                                            error_message (the one-line cause
//                                            the worker autopsy stamped).
//   2. GET /api/v1/deployments/:id/events → events[] carrying the
//                                            failure_autopsy with reason +
//                                            non-empty last_lines + hint, newest
//                                            first, count correct.
//   3. auth-negative: no / invalid bearer → 401 (the surface is gated).
//   4. cross-team: another team's token   → 404 (you can NOT read another
//                                            team's failure — never 403, no
//                                            existence leak).
//
// This mirrors the seeding pattern in deploy_events_endpoint_test.go and
// deploy_lifecycle_block_integration_test.go (real Postgres test DB via
// testhelpers.SetupTestDB, the production RequireAuth chain via
// NewTestAppWithServices), so the HTTP envelope, route resolution, JWT
// middleware, and model SQL path are exercised end-to-end against the same SQL
// the production handler issues. The producer side (worker autopsy) and this
// consumer side (the /events + /:id read) are proven schema-compatible by the
// worker's deploy_failure_autopsy_schema_parity_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// adbDeploymentEnvelope is the GET /api/v1/deployments/:id response shape (the
// item.error one-liner is the agent's first debug read).
type adbDeploymentEnvelope struct {
	OK   bool `json:"ok"`
	Item struct {
		AppID  string `json:"app_id"`
		Status string `json:"status"`
		Error  string `json:"error"`
	} `json:"item"`
}

// adbEventsEnvelope is the GET /api/v1/deployments/:id/events response shape.
type adbEventsEnvelope struct {
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

// TestDeployAutodebugPath_FailedDeploy_FullAgentLoop is the §5.1 contract:
// status+error_message AND the events autopsy AND auth-negative AND cross-team,
// asserted as one coherent debug-path test against a real test DB.
func TestDeployAutodebugPath_FailedDeploy_FullAgentLoop(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerJWT := testhelpers.MustSignSessionJWT(t,
		"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", teamID, "adb-owner@example.com")
	otherJWT := testhelpers.MustSignSessionJWT(t,
		"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", otherTeamID, "adb-other@example.com")

	// Seed a FAILED deployment with the one-line error_message the worker
	// autopsy stamps ("<reason>: <hint snippet>").
	depID := uuid.New()
	appID := "adb" + uuid.NewString()[:8]
	const wantErrorMessage = "OOMKilled: Your app exceeded its memory limit and was killed by the kernel."
	_, err := db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status, error_message)
		VALUES ($1, $2, $3, 8080, 'pro', 'failed', $4)
	`, depID, teamID, appID, wantErrorMessage)
	require.NoError(t, err)

	// Older lifecycle row + newer failure_autopsy row (the real autopsy shape).
	_, err = db.Exec(`
		INSERT INTO deployment_events
			(deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
		VALUES ($1, 'lifecycle', 'image_pull_failed', NULL, 'ErrImagePull',
			'["pulling image","ErrImagePull"]', 'check the image reference',
			now() - interval '10 minutes')
	`, depID)
	require.NoError(t, err)

	autopsyLastLines := []string{
		"npm ERR! code ELIFECYCLE",
		"FATAL: out of memory: Killed process 1 (node)",
	}
	_, err = db.Exec(`
		INSERT INTO deployment_events
			(deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
		VALUES ($1, 'failure_autopsy', 'OOMKilled', 137, 'OOMKilling: Memory cgroup out of memory',
			'["npm ERR! code ELIFECYCLE","FATAL: out of memory: Killed process 1 (node)"]',
			'Your app exceeded its memory limit and was killed by the kernel.',
			now() - interval '1 minute')
	`, depID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// ── Step 1: GET /api/v1/deployments/:id → status=failed + error_message ──
	t.Run("status_and_error_message", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID, nil)
		req.Header.Set("Authorization", "Bearer "+ownerJWT)
		req.Header.Set("X-Forwarded-For", "10.70.0.1")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var env adbDeploymentEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.True(t, env.OK)
		assert.Equal(t, appID, env.Item.AppID)
		assert.Equal(t, "failed", env.Item.Status,
			"the agent's first read must show the deploy is failed")
		assert.NotEmpty(t, env.Item.Error,
			"error_message must be non-empty — it is the one-line cause the agent acts on")
		assert.Equal(t, wantErrorMessage, env.Item.Error)
	})

	// ── Step 2: GET /api/v1/deployments/:id/events → autopsy timeline ────────
	t.Run("events_autopsy_timeline", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
		req.Header.Set("Authorization", "Bearer "+ownerJWT)
		req.Header.Set("X-Forwarded-For", "10.70.0.2")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var env adbEventsEnvelope
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		assert.True(t, env.OK)
		assert.Equal(t, depID.String(), env.DeploymentID,
			"deployment_id must echo the canonical UUID the agent can re-query")
		assert.Equal(t, 2, env.Count)
		require.Len(t, env.Events, 2)

		// Newest first (DESC by created_at): the autopsy row leads.
		autopsy := env.Events[0]
		assert.Equal(t, "failure_autopsy", autopsy.Kind,
			"the dedicated classified row is kind=failure_autopsy")
		assert.Equal(t, "OOMKilled", autopsy.Reason,
			"reason is the machine-readable classification the agent branches on")
		require.NotNil(t, autopsy.ExitCode)
		assert.Equal(t, 137, *autopsy.ExitCode)
		assert.NotEmpty(t, autopsy.LastLines,
			"last_lines (the real build/pod error tail) MUST be non-empty — "+
				"it is the surface the agent reads to fix the Dockerfile/config")
		assert.Equal(t, autopsyLastLines, autopsy.LastLines)
		assert.NotEmpty(t, autopsy.Hint,
			"hint is the plain-language remedy the agent acts on")
		assert.Contains(t, autopsy.Hint, "memory")
		assert.NotEmpty(t, autopsy.CreatedAt)

		// Older row trails.
		assert.Equal(t, "image_pull_failed", env.Events[1].Reason, "older row trails (DESC)")
		assert.Equal(t, "lifecycle", env.Events[1].Kind)
	})

	// ── Step 3: auth-negative — the debug surface is gated ───────────────────
	t.Run("auth_negative_401", func(t *testing.T) {
		// No bearer.
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
		reqNoAuth.Header.Set("X-Forwarded-For", "10.70.0.3")
		respNoAuth, err := app.Test(reqNoAuth, 5000)
		require.NoError(t, err)
		defer respNoAuth.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, respNoAuth.StatusCode,
			"no bearer → 401 (events surface is RequireAuth)")

		// Garbage bearer.
		reqBad := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
		reqBad.Header.Set("Authorization", "Bearer not-a-valid-jwt")
		reqBad.Header.Set("X-Forwarded-For", "10.70.0.4")
		respBad, err := app.Test(reqBad, 5000)
		require.NoError(t, err)
		defer respBad.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, respBad.StatusCode,
			"invalid bearer → 401")
	})

	// ── Step 4: cross-team — you can NOT read another team's failure ─────────
	t.Run("cross_team_404", func(t *testing.T) {
		// /:id (status) read.
		reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID, nil)
		reqGet.Header.Set("Authorization", "Bearer "+otherJWT)
		reqGet.Header.Set("X-Forwarded-For", "10.70.0.5")
		respGet, err := app.Test(reqGet, 5000)
		require.NoError(t, err)
		defer respGet.Body.Close()
		require.Equal(t, http.StatusNotFound, respGet.StatusCode,
			"cross-team GET /:id must be 404, never 403 (no existence leak)")

		// /events read.
		reqEv := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/events", nil)
		reqEv.Header.Set("Authorization", "Bearer "+otherJWT)
		reqEv.Header.Set("X-Forwarded-For", "10.70.0.6")
		respEv, err := app.Test(reqEv, 5000)
		require.NoError(t, err)
		defer respEv.Body.Close()
		require.Equal(t, http.StatusNotFound, respEv.StatusCode,
			"cross-team /events must be 404, never 403 (no existence leak)")

		var envelope struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		require.NoError(t, json.NewDecoder(respEv.Body).Decode(&envelope))
		assert.False(t, envelope.OK)
		assert.Equal(t, "not_found", envelope.Error)
	})
}
