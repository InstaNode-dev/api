package handlers_test

// github_deploy_getdisconnect_coverage_test.go — covers the GET + DELETE
// (Get / Disconnect) arms of the GitHub auto-deploy handler (github_deploy.go),
// which the existing github_deploy_test.go (Connect / Receive only) leaves at
// 30-37%. All DB-only; runs under CI's postgres matrix.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/testhelpers"
)

// ghSeedDeployment inserts a deployment owned by teamID and returns its app_id.
func ghSeedDeployment(t *testing.T, db *sql.DB, teamID, prefix string) string {
	t.Helper()
	appID := prefix + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)
	return appID
}

// ghConnect runs the Connect endpoint so a connection row exists for Get/Delete.
func ghConnect(t *testing.T, app *fiber.App, jwt, appID string) {
	t.Helper()
	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.21.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
}

func ghTestApp(t *testing.T, db *sql.DB, rdb *redis.Client) (*fiber.App, func()) {
	t.Helper()
	return testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage,deploy")
}

func ghDo(t *testing.T, app *fiber.App, method, path, jwt string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

func TestGitHub_Get_Arms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := ghTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "33333333-3333-3333-3333-333333333333", teamID, "g@example.com")
	appID := ghSeedDeployment(t, db, teamID, "ghg")

	t.Run("not_connected", func(t *testing.T) {
		resp := ghDo(t, app, http.MethodGet, "/api/v1/deployments/"+appID+"/github", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Connected bool `json:"connected"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		assert.False(t, body.Connected)
	})

	t.Run("connected", func(t *testing.T) {
		ghConnect(t, app, jwt, appID)
		resp := ghDo(t, app, http.MethodGet, "/api/v1/deployments/"+appID+"/github", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Connected  bool                   `json:"connected"`
			Connection map[string]interface{} `json:"connection"`
			WebhookURL string                 `json:"webhook_url"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		assert.True(t, body.Connected)
		assert.Equal(t, "octocat/hello-world", body.Connection["github_repo"])
		assert.Contains(t, body.WebhookURL, "/webhooks/github/")
	})

	t.Run("deployment_not_found", func(t *testing.T) {
		resp := ghDo(t, app, http.MethodGet, "/api/v1/deployments/nonexistent-app/github", jwt)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("cross_team_404", func(t *testing.T) {
		otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
		otherJWT := testhelpers.MustSignSessionJWT(t, "44444444-4444-4444-4444-444444444444", otherTeam, "o@example.com")
		resp := ghDo(t, app, http.MethodGet, "/api/v1/deployments/"+appID+"/github", otherJWT)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestGitHub_Disconnect_Arms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := ghTestApp(t, db, rdb)
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "55555555-5555-5555-5555-555555555555", teamID, "d@example.com")
	appID := ghSeedDeployment(t, db, teamID, "ghd")

	t.Run("idempotent_no_connection", func(t *testing.T) {
		resp := ghDo(t, app, http.MethodDelete, "/api/v1/deployments/"+appID+"/github", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Deleted bool `json:"deleted"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		assert.False(t, body.Deleted)
	})

	t.Run("happy_path_delete", func(t *testing.T) {
		ghConnect(t, app, jwt, appID)
		resp := ghDo(t, app, http.MethodDelete, "/api/v1/deployments/"+appID+"/github", jwt)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			Deleted bool `json:"deleted"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		resp.Body.Close()
		assert.True(t, body.Deleted)
	})

	t.Run("deployment_not_found", func(t *testing.T) {
		resp := ghDo(t, app, http.MethodDelete, "/api/v1/deployments/nope-app/github", jwt)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("cross_team_404", func(t *testing.T) {
		ghConnect(t, app, jwt, appID)
		otherTeam := testhelpers.MustCreateTeamDB(t, db, "pro")
		otherJWT := testhelpers.MustSignSessionJWT(t, "66666666-6666-6666-6666-666666666666", otherTeam, "x@example.com")
		resp := ghDo(t, app, http.MethodDelete, "/api/v1/deployments/"+appID+"/github", otherJWT)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		resp.Body.Close()
	})
}
