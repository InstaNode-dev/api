package handlers_test

// cross_team_isolation_test.go — security suite covering FIX-B / B44.
//
// Iron rule: a request from Team B against a resource or deployment owned
// by Team A MUST return 404 (not 403). Returning 403 leaks the existence of
// cross-tenant rows; 404 keeps the id-space fully opaque.
//
// The previous 403 "You do not own this resource/deployment" pattern was
// fixed across 18 sites (see FIX-B brief). This test exercises every one
// of those sites end-to-end through the fiber app — seeding a resource or
// deployment under Team A and hitting the endpoint with Team B's JWT.
//
// Coverage matrix:
//   resources/:id                       GET, DELETE
//   resources/:id/rotate-credentials    POST
//   resources/:id/credentials           GET (already-correct site — guards regression)
//   resources/:id/pause                 POST
//   resources/:id/resume                POST
//   resources/:id/metrics               GET
//   resources/:id/family                GET
//   resources/:id/backup                POST
//   resources/:id/backups               GET
//   resources/:id/twin                  POST
//   deployments/:id                     GET
//   deployments/:id/logs                GET
//   deployments/:id/env                 PATCH
//   deployments/:id                     DELETE
//   deployments/:id/redeploy            POST
//   deployments/:id (access-control)    PATCH (private/allowed_ips)
//   deployments/:id/github              POST, GET, DELETE
//
// Per-handler failures here are P0 — IDOR via response-code differential.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"instant.dev/internal/crypto"
	"instant.dev/internal/testhelpers"
)

// crossTeamFixture wires up two distinct teams with a resource and a
// deployment under Team A, plus a session JWT for Team B that will be
// used to probe every endpoint.
type crossTeamFixture struct {
	app           httpTester
	jwtB          string
	resourceToken string
	appID         string
	cleanup       func()
}

func setupCrossTeamFixture(t *testing.T) *crossTeamFixture {
	t.Helper()

	db, cleanDB := testhelpers.SetupTestDB(t)
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")

	cleanup := func() {
		cleanApp()
		cleanRedis()
		cleanDB()
	}

	// Team A owns the resource and deployment.
	teamAID := testhelpers.MustCreateTeamDB(t, db, "pro")
	// Team B is the attacker — wholly separate team.
	teamBID := testhelpers.MustCreateTeamDB(t, db, "pro")

	emailB := testhelpers.UniqueEmail(t)
	var userBID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamBID, emailB,
	).Scan(&userBID))
	jwtB := testhelpers.MustSignSessionJWT(t, userBID, teamBID, emailB)

	// Seed a postgres resource owned by Team A. Tier=pro so pause/resume
	// + backup endpoints aren't blocked by the 402 tier gate (the
	// ownership check runs first either way, but a 402 would be a
	// confusing mismatch in the test report).
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	encURL, err := crypto.Encrypt(aesKey, "postgres://owner:pw@host:5432/db")
	require.NoError(t, err)

	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status, env, connection_url)
		VALUES ($1::uuid, 'postgres', 'pro', 'paused', 'production', $2)
		RETURNING token::text
	`, teamAID, encURL).Scan(&resourceToken))

	// Status='paused' lets the Resume cross-team test exercise the
	// ownership branch BEFORE the not-paused-state branch. (Pause's
	// 409 already_paused never fires because the ownership check
	// runs first.)

	// Seed a deployment owned by Team A. Use a unique app_id so two
	// fixtures from different t.Run subtests don't collide.
	appID := "fix-b-" + strings.ReplaceAll(teamAID, "-", "")[:12]
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO deployments (team_id, app_id, port, tier, status, env, provider_id)
		VALUES ($1::uuid, $2, 8080, 'pro', 'healthy', 'production', 'k8s-fakeprov-1')
	`, teamAID, appID)
	require.NoError(t, err)

	return &crossTeamFixture{
		app:           app,
		jwtB:          jwtB,
		resourceToken: resourceToken,
		appID:         appID,
		cleanup:       cleanup,
	}
}

// expect404 runs a request with Team B's JWT and asserts the response is
// 404 with the canonical "not_found" error code. The body MUST NOT contain
// the string "forbidden" or "You do not own" — those would indicate the
// old 403 leak shape.
func expect404(t *testing.T, app httpTester, req *http.Request, label string) {
	t.Helper()
	resp, err := app.Test(req, 10000)
	require.NoError(t, err, "%s: app.Test failed", label)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"%s: cross-team must return 404 (not 403); got %d, body=%s",
		label, resp.StatusCode, body)

	assert.NotContains(t, body, "You do not own",
		"%s: response body must not leak the old 'You do not own' phrase", label)
	assert.NotContains(t, body, `"forbidden"`,
		"%s: response body must not echo 'forbidden' error code", label)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal(bodyBytes, &parsed),
		"%s: response body must be valid JSON; body=%s", label, body)
	assert.Equal(t, "not_found", parsed["error"],
		"%s: error code must be 'not_found'", label)
}

// ─────────────────────────────────────────────────────────────────────────────
// Resource endpoints (10 sites including the GetCredentials regression guard)
// ─────────────────────────────────────────────────────────────────────────────

// TestCrossTeam_Resource_Get_Returns404 — GET /api/v1/resources/:id.
func TestCrossTeam_Resource_Get_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken, nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/resources/:id")
}

// TestCrossTeam_Resource_Delete_Returns404 — DELETE /api/v1/resources/:id.
func TestCrossTeam_Resource_Delete_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/resources/"+fix.resourceToken, nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "DELETE /api/v1/resources/:id")
}

// TestCrossTeam_Resource_RotateCredentials_Returns404 — POST .../rotate-credentials.
func TestCrossTeam_Resource_RotateCredentials_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+fix.resourceToken+"/rotate-credentials", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/resources/:id/rotate-credentials")
}

// TestCrossTeam_Resource_GetCredentials_Returns404 — guards the already-correct
// site at resource.go:288. If anyone "fixes" this back to 403, the test catches it.
func TestCrossTeam_Resource_GetCredentials_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken+"/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/resources/:id/credentials")
}

// TestCrossTeam_Resource_Pause_Returns404 — POST .../pause.
func TestCrossTeam_Resource_Pause_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+fix.resourceToken+"/pause", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/resources/:id/pause")
}

// TestCrossTeam_Resource_Resume_Returns404 — POST .../resume.
func TestCrossTeam_Resource_Resume_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+fix.resourceToken+"/resume", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/resources/:id/resume")
}

// TestCrossTeam_Resource_Metrics_Returns404 — GET .../metrics.
func TestCrossTeam_Resource_Metrics_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/resources/:id/metrics")
}

// TestCrossTeam_Resource_Family_Returns404 — GET .../family.
func TestCrossTeam_Resource_Family_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken+"/family", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/resources/:id/family")
}

// TestCrossTeam_Resource_Backup_Returns404 — POST .../backup.
func TestCrossTeam_Resource_Backup_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+fix.resourceToken+"/backup", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/resources/:id/backup")
}

// TestCrossTeam_Resource_Backups_List_Returns404 — GET .../backups.
func TestCrossTeam_Resource_Backups_List_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken+"/backups", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/resources/:id/backups")
}

// TestCrossTeam_Resource_Twin_Returns404 — POST .../twin.
func TestCrossTeam_Resource_Twin_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	bodyBuf := bytes.NewBufferString(`{"env":"staging"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/resources/"+fix.resourceToken+"/twin", bodyBuf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/resources/:id/twin")
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment endpoints (8 sites)
// ─────────────────────────────────────────────────────────────────────────────

// TestCrossTeam_Deploy_Get_Returns404 — GET /deploy/:id.
func TestCrossTeam_Deploy_Get_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+fix.appID, nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /deploy/:id")
}

// TestCrossTeam_Deploy_Logs_Returns404 — GET /deploy/:id/logs.
func TestCrossTeam_Deploy_Logs_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+fix.appID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /deploy/:id/logs")
}

// TestCrossTeam_Deploy_UpdateEnv_Returns404 — PATCH /deploy/:id/env.
func TestCrossTeam_Deploy_UpdateEnv_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	bodyBuf := bytes.NewBufferString(`{"env":{"FOO":"bar"}}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/deploy/"+fix.appID+"/env", bodyBuf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "PATCH /deploy/:id/env")
}

// TestCrossTeam_Deploy_Delete_Returns404 — DELETE /deploy/:id.
func TestCrossTeam_Deploy_Delete_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodDelete, "/deploy/"+fix.appID, nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "DELETE /deploy/:id")
}

// TestCrossTeam_Deploy_Redeploy_Returns404 — POST /deploy/:id/redeploy.
func TestCrossTeam_Deploy_Redeploy_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	// Multipart with a fake tarball — the ownership check fires before
	// the tarball is inspected, so the contents don't matter.
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	fw, err := w.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball"))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	req := httptest.NewRequest(http.MethodPost,
		"/deploy/"+fix.appID+"/redeploy", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /deploy/:id/redeploy")
}

// TestCrossTeam_Deploy_PrivatePatch_Returns404 — PATCH /api/v1/deployments/:id
// (access-control edits — deploy_private.go).
func TestCrossTeam_Deploy_PrivatePatch_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	bodyBuf := bytes.NewBufferString(`{"private":true,"allowed_ips":["1.2.3.4"]}`)
	req := httptest.NewRequest(http.MethodPatch,
		"/api/v1/deployments/"+fix.appID, bodyBuf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "PATCH /api/v1/deployments/:id")
}

// TestCrossTeam_GitHubDeploy_Connect_Returns404 — POST /api/v1/deployments/:id/github.
func TestCrossTeam_GitHubDeploy_Connect_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	bodyBuf := bytes.NewBufferString(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+fix.appID+"/github", bodyBuf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "POST /api/v1/deployments/:id/github")
}

// TestCrossTeam_GitHubDeploy_Get_Returns404 — GET /api/v1/deployments/:id/github.
func TestCrossTeam_GitHubDeploy_Get_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/deployments/"+fix.appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "GET /api/v1/deployments/:id/github")
}

// TestCrossTeam_GitHubDeploy_Disconnect_Returns404 — DELETE .../github.
func TestCrossTeam_GitHubDeploy_Disconnect_Returns404(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/deployments/"+fix.appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	expect404(t, fix.app, req, "DELETE /api/v1/deployments/:id/github")
}

// ─────────────────────────────────────────────────────────────────────────────
// Latent IDOR — JWT carrying tid="00000000-..." must NOT match unclaimed rows
// (FIX-B finding #164 / B45-F3). Without the `!Valid` guard, the zero UUID in
// the JWT compared equal to the zero UUID in resources.team_id for unclaimed
// anonymous rows. This test pins the fix in place.
// ─────────────────────────────────────────────────────────────────────────────

// TestCrossTeam_ZeroUUID_JWT_CannotAccessUnclaimedAnonymous verifies that a
// session JWT minted with tid="00000000-0000-0000-0000-000000000000" cannot
// reach an anonymous (unclaimed, team_id IS NULL) resource via the management
// API. Pre-fix this returned 200 on Get/Metrics/Family because UUID equality
// matched the zero-value NullUUID.UUID.
func TestCrossTeam_ZeroUUID_JWT_CannotAccessUnclaimedAnonymous(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestApp(t, db, rdb)
	defer cleanApp()

	// Seed an anonymous resource — team_id IS NULL (the default for the
	// /db/new / /cache/new flow before claim).
	var resourceToken string
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO resources (resource_type, tier, status)
		VALUES ('postgres', 'anonymous', 'active')
		RETURNING token::text
	`).Scan(&resourceToken))

	// Mint a session JWT whose tid is the zero UUID. parseTeamID accepts
	// any well-formed UUID, so this JWT is "valid" but points at a team
	// that doesn't exist.
	zeroTeam := "00000000-0000-0000-0000-000000000000"
	zeroUser := "00000000-0000-0000-0000-000000000001"
	jwt := testhelpers.MustSignSessionJWT(t, zeroUser, zeroTeam, "zero@example.com")

	// Exercise the two sites where the latent bug lived: Get + Delete.
	// Both must 404. Pre-fix, the `resource.TeamID.UUID != teamID` check
	// did NOT also check `.Valid`, so the zero UUID matched an unclaimed
	// row and the handler proceeded as if the caller owned it.
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/resources/" + resourceToken},
		{http.MethodDelete, "/api/v1/resources/" + resourceToken},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		bodyBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		require.Equal(t, http.StatusNotFound, resp.StatusCode,
			"%s %s: zero-UUID JWT must NOT match unclaimed anonymous resource; got %d, body=%s",
			tc.method, tc.path, resp.StatusCode, string(bodyBytes))
	}

	// Belt-and-braces: the row must still exist and still be unclaimed.
	var teamID *string
	require.NoError(t, db.QueryRow(
		`SELECT team_id::text FROM resources WHERE token = $1::uuid`,
		resourceToken,
	).Scan(&teamID))
	require.Nil(t, teamID,
		"anonymous resource must remain unclaimed (team_id NULL) — the failed access must not have side-effected the row")
}

// ─────────────────────────────────────────────────────────────────────────────
// Smoke check: the helpers.go codeToAgentAction entry for "not_found" is what
// drives the agent-action message on cross-team 404. This test pins the body
// shape so a future refactor of codeToAgentAction can't silently change it.
// ─────────────────────────────────────────────────────────────────────────────

func TestCrossTeam_404_BodyShape_CarriesAgentAction(t *testing.T) {
	fix := setupCrossTeamFixture(t)
	defer fix.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/resources/"+fix.resourceToken, nil)
	req.Header.Set("Authorization", "Bearer "+fix.jwtB)
	resp, err := fix.app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "not_found", body["error"])
	// agent_action should be present and start with "Tell the user" per
	// the codeToAgentAction convention. Don't assert exact wording — only
	// the shape, so message tweaks don't break this test.
	action, _ := body["agent_action"].(string)
	assert.NotEmpty(t, action,
		"404 cross-team response must carry agent_action so MCP can prompt the user")
	assert.True(t,
		strings.HasPrefix(action, "Tell the user") ||
			strings.HasPrefix(action, "Tell the agent"),
		"agent_action should start with 'Tell the user/agent'; got %q", action)

	// Existence-leak guard — none of these fields should appear on a
	// cross-team 404.
	for _, leaky := range []string{"connection_url", "tier", "resource_type",
		"team_id", "owner", "owner_team_id"} {
		_, present := body[leaky]
		assert.False(t, present,
			"cross-team 404 must NOT expose %q (would leak existence); body=%v",
			leaky, body)
	}
}

// Ensure fmt is used so goimports doesn't drop it on the next pass.
var _ = fmt.Sprintf
