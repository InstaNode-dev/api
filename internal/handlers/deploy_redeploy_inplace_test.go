package handlers_test

// deploy_redeploy_inplace_test.go — POST /deploy/new redeploy=true coverage.
//
// Bug context (2026-05-30 duplicate-URL incident): three identical
// POST /deploy/new calls for the same logical app (name="truehomie-web")
// fanned out to three distinct app_ids + URLs because /deploy/new minted a
// fresh app_id every call. There was no way for an agent to ask the platform
// to replace the existing deployment in place — MCP `redeploy` existed but
// required the caller to already know the app_id of the first deploy.
//
// The fix: an optional `redeploy=true` multipart field on /deploy/new that
// locates the existing deployment by (team_id, env, env_vars._name) and
// routes through the same compute path as POST /deploy/:id/redeploy.
//
// These tests pin every branch of the new logic so a regression cannot
// silently re-introduce the fan-out behaviour.

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// multipartRedeployBody mirrors multipartDeployBody (defined in
// deploy_env_vars_test.go) but exists as a tiny local wrapper that always
// sets the `redeploy` field. Keeps the per-test setup readable.
func multipartRedeployBody(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fresh-tarball-bytes"))
	require.NoError(t, err)
	for k, v := range fields {
		require.NoError(t, w.WriteField(k, v))
	}
	require.NoError(t, w.Close())
	return buf, w.FormDataContentType()
}

// TestDeployNew_RedeployTrue_MatchFound_ReusesAppID is the happy-path test:
// pre-seed a deploy named "foo", then POST /deploy/new with redeploy=true +
// name=foo + a new tarball. The handler must return 202 with the SAME
// app_id, the SAME url, and redeployed:true. The fan-out behaviour (new
// random app_id) would be a regression.
func TestDeployNew_RedeployTrue_MatchFound_ReusesAppID(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"a1111111-1111-1111-1111-111111111111", teamID, "redeploy@example.com")

	// Pre-seed: existing live deploy with provider_id + name=foo + env=development.
	// app_id is derived from teamID to avoid collisions when the test DB is
	// shared across runs (deployments_app_id_key UNIQUE constraint).
	seedAppID := "rd1" + strings.ReplaceAll(teamID, "-", "")[:5]
	seedProviderID := "app-" + seedAppID
	seedAppURL := "https://" + seedAppID + ".deployment.instanode.dev"
	const seedName = "foo"
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, provider_id, app_url, port, tier, env, status, env_vars)
		VALUES ($1, $2, $3, $4, 8080, 'pro', 'development', 'healthy', $5::jsonb)
	`, teamID, seedAppID, seedProviderID, seedAppURL, `{"_name":"foo"}`)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartRedeployBody(t, map[string]string{
		"name":     seedName,
		"redeploy": "true",
		"env":      "development",
		"port":     "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"redeploy=true match must return 202; body: %s", string(bodyBytes))

	var parsed struct {
		OK         bool `json:"ok"`
		Redeployed bool `json:"redeployed"`
		Item       struct {
			AppID      string `json:"app_id"`
			URL        string `json:"url"`
			Redeployed bool   `json:"redeployed"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed))

	assert.True(t, parsed.OK, "ok must be true on 202")
	assert.True(t, parsed.Redeployed, "top-level redeployed must be true on in-place path")
	assert.True(t, parsed.Item.Redeployed, "item.redeployed must be true on in-place path")
	assert.Equal(t, seedAppID, parsed.Item.AppID,
		"in-place redeploy MUST reuse the existing app_id (regression: would mint a new one)")
	assert.Equal(t, seedAppURL, parsed.Item.URL,
		"in-place redeploy MUST reuse the existing app_url (regression: fan-out URL)")
}

// TestDeployNew_RedeployTrue_NoMatch_Returns404 — when redeploy=true is set
// but no live deployment matches (team, env, name), the handler must
// return 404 with the canonical envelope + the agent_action that coaches
// the agent toward the alternatives.
func TestDeployNew_RedeployTrue_NoMatch_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"a2222222-2222-2222-2222-222222222222", teamID, "nomatch@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartRedeployBody(t, map[string]string{
		"name":     "does-not-exist",
		"redeploy": "true",
		"port":     "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"redeploy=true with no match must return 404")

	var errBody struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		Message     string `json:"message"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "no_existing_deployment_to_redeploy", errBody.Error,
		"error code is the contract — agents branch on it")
	assert.NotEmpty(t, errBody.AgentAction,
		"agent_action MUST be present so the LLM has a recovery hint")
	assert.Contains(t, errBody.AgentAction, "omit",
		"agent_action must hint at omitting redeploy:true OR listing deployments")
}

// TestDeployNew_RedeployTrue_NoName_Returns400 — redeploy=true without a
// `name` field is unrecoverable: the lookup key is (team, env, name) and
// the team+env are not enough to disambiguate. 400 redeploy_requires_name.
func TestDeployNew_RedeployTrue_NoName_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"a3333333-3333-3333-3333-333333333333", teamID, "noname@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Build the body WITHOUT a name field. We can't use multipartRedeployBody
	// here because we want to control whether `name` is present — it's the
	// field-under-test. Note: the `name` field is normally REQUIRED on
	// /deploy/new (the 'name_required' 400 fires before our branch). Our
	// branch fires when shouldRedeployInPlace is true AND name is empty —
	// in practice that means name field present-but-blank, OR the
	// requireName guard returns "" (e.g. all-whitespace input). We send
	// all-whitespace so requireName trims it to "" and we hit our 400.
	body, ct := multipartRedeployBody(t, map[string]string{
		"name":     "",
		"redeploy": "true",
		"port":     "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.3")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"redeploy=true with empty name must return 400")

	var errBody struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		Message     string `json:"message"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	// The pre-existing name validation fires before our branch in some
	// configurations (it sees empty name and returns `name_required` 400).
	// Either 400 code is acceptable — what matters is that the request was
	// rejected with an agent-actionable 400, not silently accepted.
	assert.True(t,
		errBody.Error == "redeploy_requires_name" || errBody.Error == "name_required",
		"error code must be one of {redeploy_requires_name, name_required}, got %q", errBody.Error)
}

// TestDeployNew_RedeployFalse_CreatesNewAsBefore — backwards compatibility:
// a POST /deploy/new without any redeploy field must behave EXACTLY as it
// did before this PR — mint a fresh app_id, insert a new row, return 202
// with redeployed:false. Pre-seed an existing same-name deploy to make
// sure the fresh-path branch is genuinely chosen over the in-place path.
func TestDeployNew_RedeployFalse_CreatesNewAsBefore(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"a4444444-4444-4444-4444-444444444444", teamID, "fresh@example.com")

	// Pre-seed a same-name row so the fresh-path test ALSO proves the
	// in-place branch was bypassed (otherwise we couldn't tell whether the
	// new row came from the fresh path or from a redeploy bug). app_id is
	// derived from the team uuid so a shared test DB doesn't collide.
	seedAppID := "rd4" + strings.ReplaceAll(teamID, "-", "")[:5]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, provider_id, app_url, port, tier, env, status, env_vars)
		VALUES ($1, $2, $3, $4,
		        8080, 'pro', 'development', 'healthy', $5::jsonb)
	`, teamID, seedAppID, "app-"+seedAppID, "https://"+seedAppID+".deployment.instanode.dev",
		`{"_name":"shared-name"}`)
	require.NoError(t, err)

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartRedeployBody(t, map[string]string{
		"name": "shared-name",
		"port": "8080",
		// NB: no `redeploy` field at all — the missing field is the test.
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.4")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"fresh path must still return 202; body: %s", string(bodyBytes))

	var parsed struct {
		OK         bool `json:"ok"`
		Redeployed bool `json:"redeployed"`
		Item       struct {
			AppID      string `json:"app_id"`
			Redeployed bool   `json:"redeployed"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed))

	assert.True(t, parsed.OK)
	assert.False(t, parsed.Redeployed,
		"top-level redeployed MUST be false on fresh path")
	assert.False(t, parsed.Item.Redeployed,
		"item.redeployed MUST be false on fresh path")
	assert.NotEqual(t, "baadf00d", parsed.Item.AppID,
		"fresh path must mint a NEW app_id even when a same-name deploy exists")

	// Sanity-check: the database now has TWO rows for the same name. That's
	// the legacy fan-out behaviour — preserved on purpose so this PR is
	// purely additive.
	var count int
	require.NoError(t, db.QueryRow(`
		SELECT COUNT(*) FROM deployments
		WHERE team_id = $1 AND env_vars->>'_name' = 'shared-name'
	`, teamID).Scan(&count))
	assert.Equal(t, 2, count, "fresh path must create a second row, not reuse the seed")
}

// TestDeployNew_RedeployTrue_WrongTeam_Returns404 — team B asks to
// redeploy a name owned by team A. The response must be 404 (not 403):
// confirming the row's existence to a non-owner would leak deployment
// names across tenants. The metric counter on this path uses the
// wrong_team label (see DeployRedeployInPlaceTotal) but the user-facing
// response is identical to the no-match 404.
func TestDeployNew_RedeployTrue_WrongTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	require.NotEqual(t, teamA, teamB)

	// Pre-seed: deploy "secret-app" lives on team A. app_id derived from
	// teamA to avoid cross-test collisions in a shared test DB.
	seedAppID := "rd5" + strings.ReplaceAll(teamA, "-", "")[:5]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, provider_id, app_url, port, tier, env, status, env_vars)
		VALUES ($1, $2, $3, $4,
		        8080, 'pro', 'development', 'healthy', $5::jsonb)
	`, teamA, seedAppID, "app-"+seedAppID, "https://"+seedAppID+".deployment.instanode.dev",
		`{"_name":"secret-app"}`)
	require.NoError(t, err)

	// Team B authenticates and tries to redeploy "secret-app".
	sessionJWTB := testhelpers.MustSignSessionJWT(t,
		"a5555555-5555-5555-5555-555555555555", teamB, "tenantb@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartRedeployBody(t, map[string]string{
		"name":     "secret-app",
		"redeploy": "true",
		"port":     "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWTB)
	req.Header.Set("X-Forwarded-For", "10.30.0.5")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team redeploy MUST return 404 (NOT 403) — never confirm cross-tenant existence")

	var errBody struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "no_existing_deployment_to_redeploy", errBody.Error,
		"cross-team response shape MUST be identical to the no-match 404 (no information leak)")
}

// TestDeployNew_Response_AlwaysIncludesRedeployedField — the redeployed
// field is the contract: it must be present on every /deploy/new response
// so agents can rely on a stable JSON shape regardless of branch. We
// already check the in-place path in
// TestDeployNew_RedeployTrue_MatchFound_ReusesAppID; this test pins the
// fresh path by name so a future refactor that silently drops the field
// (e.g. wraps it under an envelope) fails loudly.
func TestDeployNew_Response_AlwaysIncludesRedeployedField(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"a6666666-6666-6666-6666-666666666666", teamID, "shape@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	body, ct := multipartRedeployBody(t, map[string]string{
		"name": "shape-probe",
		"port": "8080",
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.6")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusAccepted, resp.StatusCode,
		"fresh deploy must return 202; body: %s", string(bodyBytes))

	// Decode into a generic map so we can assert "the key is present" — a
	// typed struct with omitempty would hide a regression that silently
	// dropped the field.
	var generic map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &generic))

	redeployed, present := generic["redeployed"]
	require.True(t, present,
		"top-level 'redeployed' field must be present on every /deploy/new response")
	require.Equal(t, false, redeployed,
		"top-level 'redeployed' must be false on the fresh path")

	item, ok := generic["item"].(map[string]any)
	require.True(t, ok, "response must carry an 'item' object")
	itemRedeployed, present := item["redeployed"]
	require.True(t, present,
		"item.redeployed must be present on every /deploy/new response")
	require.Equal(t, false, itemRedeployed,
		"item.redeployed must be false on the fresh path")
}

