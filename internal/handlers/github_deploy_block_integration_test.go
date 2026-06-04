package handlers_test

// github_deploy_block_integration_test.go — DB-backed integration coverage for
// the deploy↔GitHub link routes that the done-bar guard
// (internal/router/route_donebar_guard_test.go) previously carried in
// routeCoverageExemptions (the D17 / matrix-W6 "deploy GitHub link" rows).
// This file is their handler-integration cover so they can move
// exempt → routeTestMap.
//
// Routes covered here (by route key):
//
//   POST   /api/v1/deployments/:id/github   (Connect — wire a repo+branch)
//   GET    /api/v1/deployments/:id/github    (Get — current connection)
//   DELETE /api/v1/deployments/:id/github    (Disconnect — tear down)
//
// Each test drives the route through the PRODUCTION RequireAuth +
// PopulateTeamRole + RequireWritable chain (testhelpers.NewTestAppWithServices
// mirrors router.New) against a real Postgres (testhelpers.SetupTestDB),
// asserting the authz + state-change + response/error contract.
//
// AUTHZ MODEL (verified against internal/router/router.go:1181-1184): these
// three routes inherit only RequireAuth from the /api/v1 group plus
// RequireWritable on the two mutating verbs — there is NO RequireRole gate.
// The ownership boundary is therefore purely team-scoped: ANY member of the
// owning team (owner OR member role) may operate, and a caller from a DIFFERENT
// team gets 404 (never 403 — the platform never confirms cross-team existence).
// The matrix's "owner / member / non-member" dimension maps onto exactly that:
//   - owner   → 2xx (TestGitHubDeployBlock_Connect_OwnerHappyPath et al.)
//   - member  → 2xx (TestGitHubDeployBlock_Member_SameTeam_Allowed) — proves
//     there is no false owner-only gate
//   - non-member (other team) → 404 (TestGitHubDeployBlock_*_CrossTeam_Returns404)
//   - unauthenticated → 401 (TestGitHubDeployBlock_RequireAuth_Returns401)
//
// The crypto / HMAC / rate-limit internals of the PUBLIC receive endpoint
// (/webhooks/github/:webhook_id) are covered by the existing whitebox suites
// (github_deploy_test.go, github_deploy_receive_arms_coverage_test.go); that
// route stays exempt (no session-auth chain to drive). This suite is scoped to
// the three session-authenticated /api/v1 link routes.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// ghdbServices is the service set NewTestAppWithServices must enable for the
// deploy + github-link routes to register. Named once so every test in this
// block reads identically.
const ghdbServices = "postgres,redis,mongodb,queue,webhook,storage,deploy"

// ghdbConnect issues an authenticated POST /api/v1/deployments/:id/github with
// the given JSON body and returns the raw response. Centralises the header
// wiring (Bearer + X-Forwarded-For, which the rate-limit middleware needs).
func ghdbConnect(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, appID, jwt, body, ip string,
) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// ── POST /api/v1/deployments/:id/github (Connect) ────────────────────────────

// TestGitHubDeployBlock_Connect_OwnerHappyPath pins the connect contract: a
// Pro-tier owner wires a repo+branch and gets 201 with the connection map, the
// public webhook_url, and the webhook_secret returned EXACTLY once (64-char hex
// = 32 bytes). Persisted state: the row exists with ciphertext (never the
// plaintext secret) under the deployment.
func TestGitHubDeployBlock_Connect_OwnerHappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-conn@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.1")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "owner connect must 201; body: %s", string(raw))

	var out struct {
		OK            bool                   `json:"ok"`
		Connection    map[string]interface{} `json:"connection"`
		WebhookURL    string                 `json:"webhook_url"`
		WebhookSecret string                 `json:"webhook_secret"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.Equal(t, "octocat/hello-world", out.Connection["github_repo"])
	assert.Equal(t, "main", out.Connection["branch"])
	assert.Equal(t, d.AppID, out.Connection["app_id"], "connection echoes the deployment app slug")
	assert.Contains(t, out.WebhookURL, "/webhooks/github/", "webhook URL points at the public receive endpoint")
	assert.Len(t, out.WebhookSecret, 64, "secret is 32 bytes hex = 64 chars, returned exactly once")

	// Persisted state: exactly one row for this deployment, secret stored as
	// ciphertext (NOT the plaintext returned to the caller).
	conn, err := models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	require.NoError(t, err, "connection row must be persisted")
	assert.Equal(t, "octocat/hello-world", conn.GitHubRepo)
	assert.NotEqual(t, out.WebhookSecret, conn.WebhookSecret,
		"stored webhook_secret must be ciphertext, never the plaintext returned to the caller")
}

// TestGitHubDeployBlock_Connect_DefaultsBranchToMain pins the contract that an
// omitted branch defaults to "main" (the connect handler's branch fallback).
func TestGitHubDeployBlock_Connect_DefaultsBranchToMain(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-defbranch@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world"}`, "10.50.0.2")
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	conn, err := models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "main", conn.Branch, "omitted branch must default to main")
}

// TestGitHubDeployBlock_Connect_AlreadyConnected_Returns409 pins the
// at-most-one-connection idempotency contract: a second POST collides on the
// unique (app_id) index and returns 409 already_connected with the
// disconnect-first agent_action.
func TestGitHubDeployBlock_Connect_AlreadyConnected_Returns409(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-dup@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	first := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.3")
	first.Body.Close()
	require.Equal(t, http.StatusCreated, first.StatusCode)

	second := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/other-repo","branch":"main"}`, "10.50.0.3")
	defer second.Body.Close()
	raw, _ := io.ReadAll(second.Body)
	require.Equal(t, http.StatusConflict, second.StatusCode,
		"second connect on an already-linked deployment must 409; body: %s", string(raw))

	var body struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.False(t, body.OK)
	assert.Equal(t, "already_connected", body.Error)
	assert.NotEmpty(t, body.AgentAction, "409 must coach the caller to disconnect first")
}

// TestGitHubDeployBlock_Connect_InvalidRepo_Returns400 pins the repo-format
// validation: a value that is not "owner/repo" is rejected 400 invalid_repo
// before any row is written.
func TestGitHubDeployBlock_Connect_InvalidRepo_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-badrepo@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"not-a-valid-repo","branch":"main"}`, "10.50.0.4")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "malformed repo must 400; body: %s", string(raw))

	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.False(t, body.OK)
	assert.Equal(t, "invalid_repo", body.Error)

	// No row should have been written.
	_, err := models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	var notFound *models.ErrGitHubConnectionNotFound
	assert.ErrorAs(t, err, &notFound, "a rejected connect must not persist a connection")
}

// TestGitHubDeployBlock_Connect_AnonymousTier_Returns402 pins the tier gate: an
// anonymous-tier team cannot wire GitHub auto-deploy (those tiers have zero
// deployments). 402 github_requires_paid_tier with the upgrade agent_action.
func TestGitHubDeployBlock_Connect_AnonymousTier_Returns402(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "anonymous"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-anon@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.5")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"anonymous-tier connect must 402; body: %s", string(raw))

	var body struct {
		OK          bool   `json:"ok"`
		Error       string `json:"error"`
		AgentAction string `json:"agent_action"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.False(t, body.OK)
	assert.Equal(t, "github_requires_paid_tier", body.Error)
	assert.NotEmpty(t, body.AgentAction, "402 must carry the upgrade agent_action")
}

// TestGitHubDeployBlock_Connect_HobbyTier_Allowed pins the tier-gate lower
// bound: Hobby is the lowest paid tier that CAN deploy a single app, so a Hobby
// team is permitted to wire that one app to GitHub (201, not 402).
func TestGitHubDeployBlock_Connect_HobbyTier_Allowed(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-hobby@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.6")
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"hobby tier may wire its single deploy to GitHub (201, not 402); body: %s", string(raw))
}

// TestGitHubDeployBlock_Connect_CrossTeam_Returns404 pins the cross-team
// isolation contract on the write route: a signed-in caller from team B trying
// to wire team A's deployment gets 404 (never 403, never a 201 that leaks the
// deployment's existence).
func TestGitHubDeployBlock_Connect_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "ghdb-connxt@example.com")
	d := seedInternalDeploy(t, db, teamA, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	resp := ghdbConnect(t, app, d.AppID, jwtB, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.7")
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team connect must 404, never 403 (no existence leak)")

	// And nothing was written for team A's deployment.
	_, err := models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	var notFound *models.ErrGitHubConnectionNotFound
	assert.ErrorAs(t, err, &notFound, "a cross-team connect must not persist a connection")
}

// TestGitHubDeployBlock_RequireAuth_Returns401 pins the unauthenticated
// contract: with no Bearer token the /api/v1 group's RequireAuth rejects all
// three link routes with 401 before any handler runs.
func TestGitHubDeployBlock_RequireAuth_Returns401(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	cases := []struct {
		name   string
		method string
		body   io.Reader
		ctype  string
	}{
		{"connect", http.MethodPost, strings.NewReader(`{"repo":"octocat/hello-world"}`), "application/json"},
		{"get", http.MethodGet, nil, ""},
		{"disconnect", http.MethodDelete, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/deployments/"+d.AppID+"/github", tc.body)
			if tc.ctype != "" {
				req.Header.Set("Content-Type", tc.ctype)
			}
			req.Header.Set("X-Forwarded-For", "10.50.0.8")
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusUnauthorized, resp.StatusCode,
				"%s without a session token must 401", tc.name)
		})
	}
}

// TestGitHubDeployBlock_Member_SameTeam_Allowed pins the authz model: a
// non-owner MEMBER of the owning team can drive all three link routes (these
// routes carry NO RequireRole gate — only team scope). This is the explicit
// "member is allowed" leg that proves there is no false owner-only gate.
func TestGitHubDeployBlock_Member_SameTeam_Allowed(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	// A non-owner member: same team_id, role="member". The link routes gate on
	// team scope, not role, so this session must be fully able to operate.
	member, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "member")
	require.NoError(t, err)
	jwt := testhelpers.MustSignSessionJWT(t, member.ID.String(), teamID.String(), "ghdb-member@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	// Member can connect.
	connResp := ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.9")
	connResp.Body.Close()
	require.Equal(t, http.StatusCreated, connResp.StatusCode, "a same-team member may connect (no owner-only gate)")

	// Member can read it back.
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/github", nil)
	getReq.Header.Set("Authorization", "Bearer "+jwt)
	getReq.Header.Set("X-Forwarded-For", "10.50.0.9")
	getResp, err := app.Test(getReq, 5000)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode, "a same-team member may read the connection")

	// Member can disconnect.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/github", nil)
	delReq.Header.Set("Authorization", "Bearer "+jwt)
	delReq.Header.Set("X-Forwarded-For", "10.50.0.9")
	delResp, err := app.Test(delReq, 5000)
	require.NoError(t, err)
	delResp.Body.Close()
	require.Equal(t, http.StatusOK, delResp.StatusCode, "a same-team member may disconnect")

	_, err = models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	var notFound *models.ErrGitHubConnectionNotFound
	assert.ErrorAs(t, err, &notFound, "disconnect must remove the connection row")
}

// ── GET /api/v1/deployments/:id/github (Get) ─────────────────────────────────

// TestGitHubDeployBlock_Get_ConnectedShape pins the read contract for a
// connected deployment: connected=true, the connection map WITHOUT the webhook
// secret (returned only once on Connect), and the public webhook_url.
func TestGitHubDeployBlock_Get_ConnectedShape(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-get@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	// Establish a connection first.
	ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.10").Body.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.10")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "get connected must 200; body: %s", string(raw))

	var out struct {
		OK         bool                   `json:"ok"`
		Connected  bool                   `json:"connected"`
		Connection map[string]interface{} `json:"connection"`
		WebhookURL string                 `json:"webhook_url"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.True(t, out.Connected)
	assert.Equal(t, "octocat/hello-world", out.Connection["github_repo"])
	_, hasSecret := out.Connection["webhook_secret"]
	assert.False(t, hasSecret, "GET must never re-surface the webhook secret")
	assert.Contains(t, out.WebhookURL, "/webhooks/github/")
}

// TestGitHubDeployBlock_Get_NotConnectedShape pins the read contract for a
// deployment with no connection: 200 connected=false, connection=nil. The
// "not connected" state is a normal 200, not a 404 (the deployment exists).
func TestGitHubDeployBlock_Get_NotConnectedShape(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-getnc@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.11")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "get not-connected must still 200; body: %s", string(raw))

	var out struct {
		OK         bool        `json:"ok"`
		Connected  bool        `json:"connected"`
		Connection interface{} `json:"connection"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.False(t, out.Connected, "an unwired deployment reports connected=false")
	assert.Nil(t, out.Connection)
}

// TestGitHubDeployBlock_Get_CrossTeam_Returns404 pins the read-route authz
// contract: team B reading team A's deployment connection gets 404, never 403.
func TestGitHubDeployBlock_Get_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtA := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamA.String(), "ghdb-getxt-a@example.com")
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "ghdb-getxt-b@example.com")
	d := seedInternalDeploy(t, db, teamA, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	// Team A wires a real connection so the cross-team read has something it
	// must NOT be able to see.
	ghdbConnect(t, app, d.AppID, jwtA, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.12").Body.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Forwarded-For", "10.50.0.13")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team connection read must 404, never 403 (no existence leak)")
}

// ── DELETE /api/v1/deployments/:id/github (Disconnect) ───────────────────────

// TestGitHubDeployBlock_Disconnect_RemovesConnection pins the disconnect happy
// path: an owner tears down an existing connection (200 deleted=true) and the
// row is gone. The deployment itself stays.
func TestGitHubDeployBlock_Disconnect_RemovesConnection(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-del@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	ghdbConnect(t, app, d.AppID, jwt, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.14").Body.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.14")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "disconnect must 200; body: %s", string(raw))

	var out struct {
		OK      bool `json:"ok"`
		Deleted bool `json:"deleted"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.True(t, out.Deleted)

	_, err = models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	var notFound *models.ErrGitHubConnectionNotFound
	assert.ErrorAs(t, err, &notFound, "the connection row must be gone after disconnect")

	// The deployment itself must survive the disconnect.
	stored, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err, "disconnect tears down only the wiring, not the deployment")
	assert.Equal(t, d.AppID, stored.AppID)
}

// TestGitHubDeployBlock_Disconnect_Idempotent pins the idempotency contract: a
// DELETE on a deployment with no connection is a no-op success (200
// deleted=false), not a 404 or 500.
func TestGitHubDeployBlock_Disconnect_Idempotent(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "ghdb-delidem@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.50.0.15")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "idempotent disconnect must 200; body: %s", string(raw))

	var out struct {
		OK      bool `json:"ok"`
		Deleted bool `json:"deleted"`
	}
	require.NoError(t, json.Unmarshal(raw, &out))
	assert.True(t, out.OK)
	assert.False(t, out.Deleted, "no connection to remove → deleted=false, still a 200 success")
}

// TestGitHubDeployBlock_Disconnect_CrossTeam_Returns404 pins the unlink-route
// authz contract: team B disconnecting team A's deployment gets 404 and team
// A's connection is left intact.
func TestGitHubDeployBlock_Disconnect_CrossTeam_Returns404(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwtA := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamA.String(), "ghdb-delxt-a@example.com")
	jwtB := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamB.String(), "ghdb-delxt-b@example.com")
	d := seedInternalDeploy(t, db, teamA, "healthy", map[string]string{})

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, ghdbServices)
	defer cleanApp()

	ghdbConnect(t, app, d.AppID, jwtA, `{"repo":"octocat/hello-world","branch":"main"}`, "10.50.0.16").Body.Close()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+d.AppID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwtB)
	req.Header.Set("X-Forwarded-For", "10.50.0.17")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team disconnect must 404, never 403")

	// Team A's connection must survive the rejected cross-team unlink.
	_, err = models.GetGitHubConnectionByAppID(context.Background(), db, d.ID)
	require.NoError(t, err, "a rejected cross-team disconnect must not delete the owner's connection")
}
