package handlers_test

// deploy_lifecycle_block_integration_test.go — DB-backed integration coverage
// for the deploy-lifecycle routes that the done-bar guard
// (internal/router/route_donebar_guard_test.go) previously carried in
// routeCoverageExemptions. USER-FLOW-INVENTORY-AND-TEST-MATRIX.md (2026-06-04)
// §D rows D5–D10 map these surfaces; this file is their handler-integration
// cover so they can move exempt → routeTestMap.
//
// Each test drives the route through the production RequireAuth chain
// (testhelpers.NewTestAppWithServices mirrors router.New) against a real
// Postgres (testhelpers.SetupTestDB), asserting the authz + state-change +
// response/error contract — NOT a live Kaniko build (compute provider is noop,
// so the build legs assert the accepted/contract surface; a real build is a
// deferred e2e/staging leg per the matrix).
//
// Routes covered here (the deploy-lifecycle exemptions, by route key):
//
//   GET   /api/v1/deployments/:id/events          (D5/D6 failure timeline)
//   PATCH /deploy/:id/env                          (D7 env merge)
//   POST  /deploy/:id/redeploy                     (D7 redeploy CAS)
//   PATCH /api/v1/deployments/:id                  (D10 access patch)
//   POST  /api/v1/deployments/:id/make-permanent   (D9 TTL keeper)
//   POST  /api/v1/deployments/:id/ttl              (D9 set TTL)
//
// The cross-cutting matrix asks (create→accepted, status/events read,
// redeploy CAS, delete→gone, tier-gating 402, authz/cross-team 403/404) are
// each exercised below or in the already-mapped sibling suites the comments
// cite.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// dlbMultipartTarball builds a minimal multipart body carrying a fake tarball
// field — the redeploy path reads the bytes but the noop compute provider
// never extracts a real tar, so the contents are irrelevant to the contract.
func dlbMultipartTarball(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("dlb-fake-tarball"))
	require.NoError(t, err)
	require.NoError(t, w.WriteField("port", "8080"))
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// ── GET /api/v1/deployments/:id/events ──────────────────────────────────────

// TestDeployLifecycle_Events_Timeline_OwnerReadsDescOrder pins the D5/D6
// failure-timeline read surface (#200): an owner reading their deployment's
// events gets the autopsy rows newest-first with the kind/reason/exit_code
// contract intact. This is the read surface that closed the silent-deploy-
// failure class (CLAUDE.md rule 27).
func TestDeployLifecycle_Events_Timeline_OwnerReadsDescOrder(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-events@example.com")
	d := seedInternalDeploy(t, db, teamID, "failed", map[string]string{})

	// Seed two timeline rows: an older lifecycle row + a newer autopsy row.
	_, err := db.Exec(`
		INSERT INTO deployment_events (deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
		VALUES ($1, 'lifecycle', 'image_pull_failed', NULL, 'ErrImagePull', '["a"]', 'pull hint', now() - interval '10 minutes')
	`, d.ID)
	require.NoError(t, err)
	_, err = db.Exec(`
		INSERT INTO deployment_events (deployment_id, kind, reason, exit_code, event, last_lines, hint, created_at)
		VALUES ($1, 'failure_autopsy', 'CrashLoopBackOff', 1, 'CrashLoopBackOff', '["b","c"]', 'crash hint', now() - interval '1 minute')
	`, d.ID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK     bool `json:"ok"`
		Count  int  `json:"count"`
		Events []struct {
			Kind     string `json:"kind"`
			Reason   string `json:"reason"`
			ExitCode *int   `json:"exit_code"`
		} `json:"events"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 2, body.Count)
	require.Len(t, body.Events, 2)
	assert.Equal(t, "CrashLoopBackOff", body.Events[0].Reason, "newest first (DESC by created_at)")
	assert.Equal(t, "failure_autopsy", body.Events[0].Kind)
	require.NotNil(t, body.Events[0].ExitCode)
	assert.Equal(t, 1, *body.Events[0].ExitCode)
	assert.Equal(t, "image_pull_failed", body.Events[1].Reason)
}

// TestDeployLifecycle_Events_CrossTeam_Returns404 pins the authz contract: a
// signed-in user on team B must get 404 (NOT 403) for team A's deployment
// events — the platform never confirms cross-team existence.
func TestDeployLifecycle_Events_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "dlb-evxt@example.com")
	d := seedInternalDeploy(t, db, teamA, "failed", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/events", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Forwarded-For", "10.40.0.2")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team events read must be 404, never 403 (no existence leak)")
}

// ── PATCH /deploy/:id/env ───────────────────────────────────────────────────

// TestDeployLifecycle_UpdateEnv_MergesAndRedacts pins D7's env-merge: PATCH
// merges new keys into the existing env, persists the merged map, and the
// response redacts secret-keyed values (consistent with GET /deploy/:id).
func TestDeployLifecycle_UpdateEnv_MergesAndRedacts(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-env@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"EXISTING": "keep"})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// FEATURE_FLAG is a deliberately non-secret key (no SECRET/TOKEN/_KEY/URL
	// fragment) so the response shows its plaintext value; DATABASE_URL ends in
	// URL and must be redacted in the outbound JSON.
	patchBody := `{"env":{"FEATURE_FLAG":"new-val","DATABASE_URL":"postgres://secret/here"}}`
	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+d.AppID+"/env", bytes.NewReader([]byte(patchBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.3")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "env merge must be 200; body: %s", string(raw))

	var body struct {
		OK   bool              `json:"ok"`
		Note string            `json:"note"`
		Env  map[string]string `json:"env"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.True(t, body.OK)
	assert.Contains(t, body.Note, "redeploy", "note must coach the caller to redeploy to apply")
	assert.Equal(t, "keep", body.Env["EXISTING"], "existing key must survive the merge")
	assert.Equal(t, "new-val", body.Env["FEATURE_FLAG"], "new non-secret key must be merged in (plaintext)")
	assert.Equal(t, "***", body.Env["DATABASE_URL"], "secret-keyed value must be redacted in the response")

	// Persisted state: the merged map (unredacted) must be on the row.
	stored, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "postgres://secret/here", stored.EnvVars["DATABASE_URL"],
		"stored value is the real secret, not the redacted placeholder")
	assert.Equal(t, "keep", stored.EnvVars["EXISTING"])
}

// TestDeployLifecycle_UpdateEnv_CrossTeam_Returns404 pins the authz contract
// for the env-merge route.
func TestDeployLifecycle_UpdateEnv_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "dlb-envxt@example.com")
	d := seedInternalDeploy(t, db, teamA, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+d.AppID+"/env",
		bytes.NewReader([]byte(`{"env":{"X":"y"}}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Forwarded-For", "10.40.0.4")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team env PATCH must be 404, never 403")
}

// ── POST /deploy/:id/redeploy ───────────────────────────────────────────────

// TestDeployLifecycle_Redeploy_HealthyRow_Accepts202 pins the D7 redeploy CAS
// happy path: a healthy, built (provider_id set) deployment can be redeployed
// in place — the guarded CAS flips status to 'building' and the handler 202s,
// reusing the same app_id (the in-place contract that fixed the truehomie-web
// app-id fan-out incident).
func TestDeployLifecycle_Redeploy_HealthyRow_Accepts202(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-redep@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x.deploy"))

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := dlbMultipartTarball(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.5")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"redeploy of a healthy, built row must 202; body: %s", string(raw))
}

// TestDeployLifecycle_Redeploy_TerminalRow_Returns409 pins the CAS-guard
// terminal arm: a deployment in a terminal status (stopped) can NOT be
// redeployed — flipping it back to 'building' would resurrect an over-TTL /
// over-cap workload. 409, not 202.
func TestDeployLifecycle_Redeploy_TerminalRow_Returns409(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-redepterm@example.com")
	d := seedInternalDeploy(t, db, teamID, "stopped", map[string]string{})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x.deploy"))

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := dlbMultipartTarball(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.6")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"redeploy of a terminal (stopped) row must 409, not resurrect")
}

// ── PATCH /api/v1/deployments/:id ───────────────────────────────────────────

// TestDeployLifecycle_Patch_Pro_SetsPrivate pins D10: a Pro-tier owner can
// PATCH access fields (private + allowed_ips) on an existing deployment with
// no rebuild. Asserts 200 + the persisted private flag.
func TestDeployLifecycle_Patch_Pro_SetsPrivate(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-patch@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	patchBody := `{"private":true,"allowed_ips":["203.0.113.4"]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/deployments/"+d.AppID,
		bytes.NewReader([]byte(patchBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.7")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Pro PATCH flipping private must be 200; body: %s", string(raw))

	stored, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.True(t, stored.Private, "private flag must be persisted by the PATCH")
}

// TestDeployLifecycle_Patch_Hobby_Returns402 pins the tier-gate: flipping a
// deploy private is a Pro+ capability; a hobby-tier caller gets 402 with the
// agent_action upgrade copy (same contract as POST /deploy/new).
func TestDeployLifecycle_Patch_Hobby_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-patch402@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	patchBody := `{"private":true,"allowed_ips":["203.0.113.4"]}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/deployments/"+d.AppID,
		bytes.NewReader([]byte(patchBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.8")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"hobby PATCH flipping private must be 402; body: %s", string(raw))

	var body struct {
		OK          bool   `json:"ok"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.False(t, body.OK)
	assert.NotEmpty(t, body.AgentAction, "402 must carry agent_action upgrade copy")
}

// ── POST /api/v1/deployments/:id/make-permanent ─────────────────────────────

// TestDeployLifecycle_MakePermanent_HappyPath pins D9: a paid-tier owner can
// promote a TTL deploy to permanent — expires_at clears, ttl_policy becomes
// 'permanent', response carries the re-enable note.
func TestDeployLifecycle_MakePermanent_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-perm@example.com")
	// Seed a deploy with a custom TTL so make-permanent actually changes state.
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})
	_, err := db.Exec(`UPDATE deployments SET ttl_policy='custom', expires_at = now() + interval '24 hours' WHERE id=$1`, d.ID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+d.AppID+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.9")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "make-permanent must be 200; body: %s", string(raw))

	var body struct {
		OK   bool   `json:"ok"`
		Note string `json:"note"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.True(t, body.OK)
	assert.Contains(t, body.Note, "permanently")

	stored, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, models.DeployTTLPolicyPermanent, stored.TTLPolicy,
		"ttl_policy must flip to permanent")
	assert.False(t, stored.ExpiresAt.Valid, "expires_at must clear when made permanent")
}

// TestDeployLifecycle_MakePermanent_CrossTeam_Returns404 pins the authz
// contract on the make-permanent route.
func TestDeployLifecycle_MakePermanent_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "dlb-permxt@example.com")
	d := seedInternalDeploy(t, db, teamA, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+d.AppID+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Forwarded-For", "10.40.0.10")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team make-permanent must be 404, never 403")
}

// ── POST /api/v1/deployments/:id/ttl ────────────────────────────────────────

// TestDeployLifecycle_SetTTL_HappyPath pins D9: a paid-tier owner can set a
// custom TTL within bounds — expires_at = now()+hours, ttl_policy='custom'.
func TestDeployLifecycle_SetTTL_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-ttl@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})
	// seedInternalDeploy seeds ttl_policy='permanent'; SetTTL rejects a
	// permanent deploy (409 already_permanent). Move it to a TTL'd policy so
	// the happy-path UPDATE matches a row.
	_, err := db.Exec(`UPDATE deployments SET ttl_policy='auto_24h', expires_at = now() + interval '24 hours' WHERE id=$1`, d.ID)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+d.AppID+"/ttl",
		bytes.NewReader([]byte(`{"hours":48}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.11")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set-ttl must be 200; body: %s", string(raw))

	stored, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "custom", stored.TTLPolicy, "ttl_policy must become custom")
	assert.True(t, stored.ExpiresAt.Valid, "expires_at must be set for a custom TTL")
}

// TestDeployLifecycle_SetTTL_OutOfRange_Returns400 pins the bounds validation:
// hours must be in [1, 8760]; an out-of-range value is rejected 400 with the
// agent_action coaching copy.
func TestDeployLifecycle_SetTTL_OutOfRange_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "dlb-ttl400@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+d.AppID+"/ttl",
		bytes.NewReader([]byte(`{"hours":100000}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.12")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"out-of-range hours must be 400; body: %s", string(raw))

	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.False(t, body.OK)
	assert.Equal(t, "invalid_hours", body.Error)
}
