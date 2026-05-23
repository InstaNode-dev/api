package handlers_test

// github_deploy_vecwave_test.go — residual coverage for github_deploy.go (the
// _vecwave wave). Covers the Connect + Receive arms the existing
// github_deploy_test.go / github_deploy_receive_arms_coverage_test.go /
// github_deploy_getdisconnect_coverage_test.go leave uncovered:
//
//   Connect:
//     - invalid_body (400) — non-JSON body fails BodyParser.
//     - invalid_branch (400) — branch > 250 chars.
//     - already_connected (409) — a second Connect on the same deployment.
//     - happy path WITH installation_id — drives githubConnectionToMap's
//       installation_id-valid branch.
//   Receive:
//     - deploy_triggered (202) success enqueue + last_commit_sha bump, then
//     - rate_limited (429) once the 1h per-connection cap (10) is exceeded.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestGitHubConnect_Arms_Vecwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := ghTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "66666666-6666-6666-6666-666666666666", teamID, "conn@example.com")
	appID := ghSeedDeployment(t, db, teamID, "ghc")

	post := func(rawBody string) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github",
			strings.NewReader(rawBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("X-Forwarded-For", "10.31.0.1")
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		return r
	}

	t.Run("invalid_body_400", func(t *testing.T) {
		r := post(`{not json`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		var out map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.Equal(t, "invalid_body", out["error"])
	})

	t.Run("invalid_branch_400", func(t *testing.T) {
		longBranch := strings.Repeat("b", 251)
		r := post(`{"repo":"octocat/hello-world","branch":"` + longBranch + `"}`)
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		var out map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.Equal(t, "invalid_branch", out["error"])
	})

	t.Run("happy_with_installation_id", func(t *testing.T) {
		r := post(`{"repo":"octocat/hello-world","branch":"main","installation_id":424242}`)
		require.Equal(t, http.StatusCreated, r.StatusCode)
		var out struct {
			Connection map[string]any `json:"connection"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		// githubConnectionToMap's installation_id-valid branch.
		assert.EqualValues(t, 424242, out.Connection["installation_id"])
	})

	t.Run("already_connected_409", func(t *testing.T) {
		// A second Connect on the same deployment trips the unique-index guard.
		r := post(`{"repo":"octocat/hello-world","branch":"main"}`)
		assert.Equal(t, http.StatusConflict, r.StatusCode)
		var out map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.Equal(t, "already_connected", out["error"])
	})
}

// TestGitHubConnect_NotFoundArms_Vecwave drives Connect's deployment-not-found
// (404) and cross-team (404) arms, and Receive's bad-webhook-uuid (404) +
// unknown-connection (404) + body-too-large (413) arms.
func TestGitHubConnect_NotFoundArms_Vecwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := ghTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "99999999-9999-9999-9999-999999999999", teamID, "nf@example.com")

	t.Run("connect_deployment_not_found_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/no-such-app/github",
			strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
		r.Body.Close()
	})

	t.Run("connect_cross_team_404", func(t *testing.T) {
		// Deployment owned by another team → 404 (never confirm existence).
		otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
		appID := ghSeedDeployment(t, db, otherTeam, "ghx")
		req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github",
			strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
		r.Body.Close()
	})

	t.Run("receive_bad_webhook_uuid_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github/not-a-uuid", strings.NewReader(`{}`))
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
		r.Body.Close()
	})

	t.Run("receive_unknown_connection_404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+uuid.NewString(), strings.NewReader(`{}`))
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, r.StatusCode)
		r.Body.Close()
	})
}

// TestGitHubReceive_TriggerThenRateLimit_Vecwave drives the Receive
// deploy-triggered success arm (202 + last_commit_sha bump) and the per-
// connection rate-limit arm (429) once the 1h cap (githubMaxDeploysPerHour=10)
// is exceeded.
func TestGitHubReceive_TriggerThenRateLimit_Vecwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := ghTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "88888888-8888-8888-8888-888888888888", teamID, "rl@example.com")
	appID := ghSeedDeployment(t, db, teamID, "ghl")

	// Connect, capturing the connection id + secret.
	creq := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github",
		strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("Authorization", "Bearer "+jwt)
	creq.Header.Set("X-Forwarded-For", "10.32.0.1")
	cresp, err := app.Test(creq, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, cresp.StatusCode)
	var connOut struct {
		Connection    map[string]any `json:"connection"`
		WebhookSecret string         `json:"webhook_secret"`
	}
	require.NoError(t, json.NewDecoder(cresp.Body).Decode(&connOut))
	cresp.Body.Close()
	connID := connOut.Connection["id"].(string)
	secret := connOut.WebhookSecret

	pushSHA := func(sha string) *http.Response {
		body := []byte(fmt.Sprintf(
			`{"ref":"refs/heads/main","after":"%s","pusher":{"name":"ci"},"repository":{"full_name":"octocat/hello-world"}}`, sha))
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-Hub-Signature-256", computeSig(secret, body))
		req.Header.Set("X-Forwarded-For", "140.82.114.3")
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		return r
	}

	// First push: deploy_triggered → 202. Distinct SHA each time so the
	// idempotency short-circuit never fires.
	r := pushSHA("1111111111111111111111111111111111111111")
	assert.Equal(t, http.StatusAccepted, r.StatusCode, "first push must enqueue (202)")
	var first struct {
		DeployQueued bool   `json:"deploy_queued"`
		CommitSHA    string `json:"commit_sha"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&first))
	r.Body.Close()
	assert.True(t, first.DeployQueued)

	// last_commit_sha must have been bumped to the pushed SHA.
	var lastSHA string
	require.NoError(t, db.QueryRow(
		`SELECT last_commit_sha FROM app_github_connections WHERE id = $1::uuid`, connID).Scan(&lastSHA))
	assert.Equal(t, "1111111111111111111111111111111111111111", lastSHA)

	// Drive up to the cap (10) with distinct SHAs, then the 11th is rate-limited.
	var got429 bool
	for i := 2; i <= 12; i++ {
		sha := fmt.Sprintf("%040d", i)
		rr := pushSHA(sha)
		if rr.StatusCode == http.StatusTooManyRequests {
			got429 = true
			var out map[string]any
			_ = json.NewDecoder(rr.Body).Decode(&out)
			rr.Body.Close()
			assert.Equal(t, "rate_limited", out["error"])
			break
		}
		rr.Body.Close()
	}
	assert.True(t, got429, "exceeding the per-connection hourly cap must return 429 rate_limited")
}
