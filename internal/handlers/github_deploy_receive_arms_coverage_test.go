package handlers_test

// github_deploy_receive_arms_coverage_test.go — covers the Receive push-event
// branch-filter arms (github_deploy.go) the existing idempotency/ping/signature
// tests don't reach: branch-mismatch, zero-SHA branch-delete, and a non-push
// event type. All DB-only.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

func TestReceiveGitHub_BranchAndEventArms(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, "77777777-7777-7777-7777-777777777777", teamID, "rcv@example.com")
	appID := "ghr" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	// Connect (tracks branch "main").
	creq := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github",
		strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`))
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("Authorization", "Bearer "+jwt)
	creq.Header.Set("X-Forwarded-For", "10.22.0.1")
	cresp, err := app.Test(creq, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, cresp.StatusCode)
	var connOut struct {
		Connection    map[string]interface{} `json:"connection"`
		WebhookSecret string                 `json:"webhook_secret"`
	}
	require.NoError(t, json.NewDecoder(cresp.Body).Decode(&connOut))
	cresp.Body.Close()
	connID := connOut.Connection["id"].(string)
	secret := connOut.WebhookSecret

	postSigned := func(event string, body []byte) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connID, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", event)
		req.Header.Set("X-Hub-Signature-256", computeSig(secret, body))
		req.Header.Set("X-Forwarded-For", "140.82.114.2")
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		return r
	}

	t.Run("non_push_event_ignored", func(t *testing.T) {
		body := []byte(`{"action":"opened"}`)
		r := postSigned("pull_request", body)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		var out struct {
			Ignored bool `json:"ignored"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.True(t, out.Ignored)
	})

	t.Run("branch_mismatch_ignored", func(t *testing.T) {
		// Push to a different branch than the tracked "main".
		body := []byte(`{"ref":"refs/heads/feature","after":"aaaa1111bbbb2222cccc3333dddd4444eeee5555","pusher":{"name":"x"},"repository":{"full_name":"octocat/hello-world"}}`)
		r := postSigned("push", body)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		var out struct {
			Ignored bool   `json:"ignored"`
			Reason  string `json:"reason"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.True(t, out.Ignored)
		assert.Equal(t, "branch_mismatch", out.Reason)
	})

	t.Run("zero_sha_branch_delete_ignored", func(t *testing.T) {
		body := []byte(`{"ref":"refs/heads/main","after":"0000000000000000000000000000000000000000","pusher":{"name":"x"},"repository":{"full_name":"octocat/hello-world"}}`)
		r := postSigned("push", body)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		var out struct {
			Ignored bool   `json:"ignored"`
			Reason  string `json:"reason"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
		r.Body.Close()
		assert.True(t, out.Ignored)
		assert.Equal(t, "no_commit", out.Reason)
	})

	t.Run("invalid_push_payload_400", func(t *testing.T) {
		r := postSigned("push", []byte(`{not json`))
		assert.Equal(t, http.StatusBadRequest, r.StatusCode)
		r.Body.Close()
	})
}

