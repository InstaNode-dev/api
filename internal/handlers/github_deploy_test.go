package handlers_test

// github_deploy_test.go — coverage for the GitHub auto-deploy endpoints.
//
// Two layers of tests live here:
//
//   1. Pure unit tests for VerifyGitHubSignature — no DB, no Fiber. Confirms
//      the HMAC contract matches GitHub's exact format ("sha256=<hex>"),
//      rejects malformed headers, and uses constant-time compare.
//
//   2. Integration tests through the Fiber test app: happy-path Connect,
//      idempotency on duplicate push events (same commit SHA = no-op),
//      tier gating for anonymous teams, signature failure on Receive.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// ── Signature verification ──────────────────────────────────────────────────

// computeSig returns the same hex string GitHub puts in the
// X-Hub-Signature-256 header for a given secret + body. Shared by every
// receive-path test in this file so the contract is centralised.
func computeSig(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyGitHubSignature_ValidPasses(t *testing.T) {
	secret := "test_secret_value_12345"
	body := []byte(`{"ref":"refs/heads/main","after":"abc123"}`)
	sig := computeSig(secret, body)

	assert.True(t, handlers.VerifyGitHubSignature(secret, body, sig),
		"correctly-signed payload must verify")
}

func TestVerifyGitHubSignature_TamperedBodyFails(t *testing.T) {
	secret := "test_secret_value_12345"
	body := []byte(`{"ref":"refs/heads/main","after":"abc123"}`)
	sig := computeSig(secret, body)

	// Mutate one byte of the body — signature must reject.
	tampered := append([]byte{}, body...)
	tampered[10] = 'X'

	assert.False(t, handlers.VerifyGitHubSignature(secret, tampered, sig),
		"mutated body must NOT verify against original signature")
}

func TestVerifyGitHubSignature_WrongSecretFails(t *testing.T) {
	body := []byte(`{"ref":"refs/heads/main","after":"abc123"}`)
	sig := computeSig("correct_secret", body)

	assert.False(t, handlers.VerifyGitHubSignature("wrong_secret", body, sig),
		"signature signed with one secret must not verify with another")
}

func TestVerifyGitHubSignature_MissingPrefixFails(t *testing.T) {
	secret := "test_secret"
	body := []byte(`{}`)

	// Header without the "sha256=" prefix — must reject.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	rawHex := hex.EncodeToString(mac.Sum(nil))

	assert.False(t, handlers.VerifyGitHubSignature(secret, body, rawHex),
		"header without 'sha256=' prefix must be rejected")
}

func TestVerifyGitHubSignature_EmptyHeaderFails(t *testing.T) {
	assert.False(t, handlers.VerifyGitHubSignature("s", []byte(`{}`), ""),
		"empty header must reject")
}

func TestVerifyGitHubSignature_NonHexFails(t *testing.T) {
	assert.False(t, handlers.VerifyGitHubSignature("s", []byte(`{}`), "sha256=not-hex-xx"),
		"non-hex signature payload must reject")
}

// ── HTTP integration ────────────────────────────────────────────────────────

// TestConnectGitHub_HappyPath verifies that a Pro-tier user can connect a
// deployment to a GitHub repo and the response carries the webhook URL +
// plaintext secret exactly once.
func TestConnectGitHub_HappyPath(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"11111111-1111-1111-1111-111111111111", teamID, "gh@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Seed a deployment row directly — Connect needs an existing
	// deployments row to point at. app_id is derived from the team_id
	// so parallel tests / repeat runs against a shared TEST_DATABASE_URL
	// don't collide on the deployments.app_id unique index.
	appID := "gh1" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.1")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"happy-path connect must 201")

	var out struct {
		OK            bool                   `json:"ok"`
		Connection    map[string]interface{} `json:"connection"`
		WebhookURL    string                 `json:"webhook_url"`
		WebhookSecret string                 `json:"webhook_secret"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.Equal(t, "octocat/hello-world", out.Connection["github_repo"])
	assert.Equal(t, "main", out.Connection["branch"])
	assert.Contains(t, out.WebhookURL, "/webhooks/github/",
		"webhook URL must point at the public receive endpoint")
	assert.NotEmpty(t, out.WebhookSecret,
		"webhook secret is returned exactly once on connect")
	assert.Len(t, out.WebhookSecret, 64,
		"webhook secret is 32 bytes hex = 64 chars")
}

// TestConnectGitHub_AnonymousRejected verifies the tier gate. An anonymous
// team (no plan tier) must be rejected with 402 — github_requires_paid_tier.
func TestConnectGitHub_AnonymousRejected(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"22222222-2222-2222-2222-222222222222", teamID, "anon@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := "gh2" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'anonymous', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.2")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusPaymentRequired, resp.StatusCode,
		"anonymous team must be 402'd by the tier gate")

	var errBody struct {
		OK         bool   `json:"ok"`
		Error      string `json:"error"`
		UpgradeURL string `json:"upgrade_url"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errBody))
	assert.False(t, errBody.OK)
	assert.Equal(t, "github_requires_paid_tier", errBody.Error)
	assert.Contains(t, errBody.UpgradeURL, "pricing",
		"upgrade_url must point at pricing")
}

// TestConnectGitHub_InvalidRepoFormat: 'repo' must be 'owner/repo' form.
// 'just-owner' and 'too/many/slashes' both reject.
func TestConnectGitHub_InvalidRepoFormat(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"33333333-3333-3333-3333-333333333333", teamID, "invalid@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := "gh3" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	cases := []string{"just-owner", "too/many/slashes/here", "", "/", "owner/"}
	for _, repo := range cases {
		t.Run(fmt.Sprintf("repo=%q", repo), func(t *testing.T) {
			body := strings.NewReader(fmt.Sprintf(`{"repo":%q,"branch":"main"}`, repo))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+sessionJWT)
			req.Header.Set("X-Forwarded-For", "10.20.0.3")

			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"malformed repo %q must reject with 400", repo)
		})
	}
}

// TestReceiveGitHub_Idempotency: two push events with the same commit SHA
// must result in only ONE enqueued pending_github_deploys row.
func TestReceiveGitHub_Idempotency(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"44444444-4444-4444-4444-444444444444", teamID, "idem@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := "gh4" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	// Connect first.
	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.4")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var connOut struct {
		Connection    map[string]interface{} `json:"connection"`
		WebhookSecret string                 `json:"webhook_secret"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&connOut))
	resp.Body.Close()

	connectionID := connOut.Connection["id"].(string)
	secret := connOut.WebhookSecret

	// Build a signed push event.
	pushBody := []byte(`{"ref":"refs/heads/main","after":"deadbeefcafef00d1234567890abcdef12345678","pusher":{"name":"octocat"},"repository":{"full_name":"octocat/hello-world"}}`)
	sig := computeSig(secret, pushBody)

	postPush := func() *http.Response {
		req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connectionID, bytes.NewReader(pushBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("X-Hub-Signature-256", sig)
		req.Header.Set("X-Forwarded-For", "140.82.114.1") // GitHub's IP range
		r, err := app.Test(req, 10000)
		require.NoError(t, err)
		return r
	}

	// First push — deploy enqueued.
	r1 := postPush()
	require.Equal(t, http.StatusAccepted, r1.StatusCode,
		"first push must 202 with deploy_queued=true")
	io.Copy(io.Discard, r1.Body)
	r1.Body.Close()

	// Second push with the same SHA — duplicate, no enqueue.
	r2 := postPush()
	require.Equal(t, http.StatusOK, r2.StatusCode,
		"duplicate push must 200 (no-op)")
	var dupOut struct {
		Duplicate bool `json:"duplicate"`
	}
	require.NoError(t, json.NewDecoder(r2.Body).Decode(&dupOut))
	r2.Body.Close()
	assert.True(t, dupOut.Duplicate,
		"duplicate flag must be set when same SHA replays")

	// Verify only ONE row in pending_github_deploys for this commit.
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM pending_github_deploys
		 WHERE connection_id = $1 AND commit_sha = $2`,
		connectionID, "deadbeefcafef00d1234567890abcdef12345678",
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count,
		"idempotency: duplicate push must NOT create a second pending row")
}

// TestReceiveGitHub_SignatureMismatchRejects: a push with a bad signature
// returns 401 and emits no pending_github_deploys row.
func TestReceiveGitHub_SignatureMismatchRejects(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"55555555-5555-5555-5555-555555555555", teamID, "sig@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := "gh5" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.5")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var connOut struct {
		Connection map[string]interface{} `json:"connection"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&connOut))
	resp.Body.Close()
	connectionID := connOut.Connection["id"].(string)

	// Sign with the WRONG secret.
	pushBody := []byte(`{"ref":"refs/heads/main","after":"abc","pusher":{"name":"u"},"repository":{"full_name":"o/r"}}`)
	badSig := computeSig("not-the-real-secret", pushBody)

	req2 := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connectionID, bytes.NewReader(pushBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-GitHub-Event", "push")
	req2.Header.Set("X-Hub-Signature-256", badSig)
	req2.Header.Set("X-Forwarded-For", "140.82.114.2")

	r, err := app.Test(req2, 10000)
	require.NoError(t, err)
	defer r.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, r.StatusCode,
		"bad signature must 401")

	// No pending row was enqueued.
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM pending_github_deploys
		 WHERE connection_id = $1`, connectionID,
	).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count,
		"signature failure must NOT enqueue a deploy")
}

// TestReceiveGitHub_PingHandshake: GitHub's "ping" event must succeed with
// 200 + pong:true regardless of branch — it's the initial handshake.
func TestReceiveGitHub_PingHandshake(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t,
		"66666666-6666-6666-6666-666666666666", teamID, "ping@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	appID := "gh6" + strings.ReplaceAll(teamID, "-", "")[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status)
		VALUES ($1, $2, 8080, 'pro', 'healthy')`, teamID, appID)
	require.NoError(t, err)

	body := strings.NewReader(`{"repo":"octocat/hello-world","branch":"main"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/deployments/"+appID+"/github", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.20.0.6")

	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var connOut struct {
		Connection    map[string]interface{} `json:"connection"`
		WebhookSecret string                 `json:"webhook_secret"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&connOut))
	resp.Body.Close()
	connectionID := connOut.Connection["id"].(string)
	secret := connOut.WebhookSecret

	// GitHub's ping event body has zen + hook fields. We only need a
	// signed body; the handler returns early without parsing.
	pingBody := []byte(`{"zen":"Practicality beats purity.","hook_id":1}`)
	sig := computeSig(secret, pingBody)

	req2 := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connectionID, bytes.NewReader(pingBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-GitHub-Event", "ping")
	req2.Header.Set("X-Hub-Signature-256", sig)
	req2.Header.Set("X-Forwarded-For", "140.82.114.3")

	r, err := app.Test(req2, 10000)
	require.NoError(t, err)
	defer r.Body.Close()

	assert.Equal(t, http.StatusOK, r.StatusCode)
	var out struct {
		OK   bool `json:"ok"`
		Pong bool `json:"pong"`
	}
	require.NoError(t, json.NewDecoder(r.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.True(t, out.Pong, "ping handshake must echo pong=true")
}
