package handlers_test

// github_app_webhook_integration_test.go — DB+Redis-gated coverage for the
// GitHub App webhook handler (POST /webhooks/github, P4.2). These tests cover
// every branch that requires a real Postgres row: installation lifecycle events
// (deleted/suspend/unsuspend), the push happy-path (matched connection →
// pending_github_deploys), push no_connection, push no_active_installation,
// and the delivery-dedup (replay) path.
//
// They skip cleanly when TEST_DATABASE_URL is not set (same guard as the
// existing daDeployNeedsDB helper).

import (
	"context"
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

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// ── test-local helpers ────────────────────────────────────────────────────────

const whibWebhookSecret = "whsectest"

// whibSign computes the X-Hub-Signature-256 value for body + secret.
func whibSign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// whibEnableWebhook is a config mutator that turns on the GitHub App webhook
// feature with the shared test secret.
func whibEnableWebhook(c *config.Config) {
	c.GitHubAppEnabled = true
	c.GitHubAppWebhookSecret = whibWebhookSecret
}

// whibPost fires POST /webhooks/github on the test Fiber app.
func whibPost(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, body []byte, event, delivery string) *http.Response {
	t.Helper()
	sig := whibSign(whibWebhookSecret, body)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	req.Header.Set("X-Hub-Signature-256", sig)
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

// whibDecodeJSON reads and decodes the entire response body into v.
func whibDecodeJSON(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, v))
}

// installationBody builds a minimal GitHub installation event JSON payload.
func installationBody(action string, installID int64, login string) []byte {
	return []byte(fmt.Sprintf(
		`{"action":%q,"installation":{"id":%d,"account":{"login":%q}}}`,
		action, installID, login,
	))
}

// pushEventBody builds a minimal GitHub push event JSON payload.
func pushEventBody(repo, branch, sha string, installID int64) []byte {
	return []byte(fmt.Sprintf(
		`{"ref":"refs/heads/%s","after":%q,"repository":{"full_name":%q},"installation":{"id":%d}}`,
		branch, sha, repo, installID,
	))
}

// ── installation deleted ──────────────────────────────────────────────────────

func TestGitHubAppWebhook_Installation_Deleted(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 100101

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	body := installationBody("deleted", installID, "acme-org")
	resp := whibPost(t, app, body, "installation", "del-001")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify the row is gone.
	_, gerr := models.GetGitHubInstallation(ctx, db, installID)
	require.Error(t, gerr, "installation row should be deleted")
	var nf *models.ErrGitHubInstallationNotFound
	assert.ErrorAs(t, gerr, &nf)
}

// ── installation suspend ──────────────────────────────────────────────────────

func TestGitHubAppWebhook_Installation_Suspend(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 100102

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	body := installationBody("suspend", installID, "acme-org")
	resp := whibPost(t, app, body, "installation", "sus-001")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	inst, gerr := models.GetGitHubInstallation(ctx, db, installID)
	require.NoError(t, gerr)
	assert.True(t, inst.SuspendedAt.Valid, "SuspendedAt should be set after suspend event")
}

// ── installation unsuspend ────────────────────────────────────────────────────

func TestGitHubAppWebhook_Installation_Unsuspend(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 100103

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	// Suspend first so there is something to clear.
	require.NoError(t, models.SetGitHubInstallationSuspended(ctx, db, installID, true))

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	body := installationBody("unsuspend", installID, "acme-org")
	resp := whibPost(t, app, body, "installation", "unsu-001")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	inst, gerr := models.GetGitHubInstallation(ctx, db, installID)
	require.NoError(t, gerr)
	assert.False(t, inst.SuspendedAt.Valid, "SuspendedAt should be NULL after unsuspend event")
}

// ── push happy path → 202 enqueued ───────────────────────────────────────────

func TestGitHubAppWebhook_Push_HappyPath_202(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 200201

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	// Seed a deployments row with an explicit UUID for the FK.
	deploymentUUID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'healthy')`,
		deploymentUUID, teamID, "ghwh-"+deploymentUUID.String()[:8])
	require.NoError(t, err)

	// Wire a github connection: repo="owner/testrepo", branch="main".
	instID64 := installID
	conn, cerr := models.CreateGitHubConnection(ctx, db, models.CreateGitHubConnectionParams{
		AppID:          deploymentUUID,
		TeamID:         teamID,
		GitHubRepo:     "owner/testrepo",
		Branch:         "main",
		WebhookSecret:  "placeholder_encrypted_secret",
		InstallationID: &instID64,
	})
	require.NoError(t, cerr)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	const commitSHA = "aabbccdd11223344556677889900aabbccdd1122"
	body := pushEventBody("owner/testrepo", "main", commitSHA, installID)
	resp := whibPost(t, app, body, "push", "push-happy-001")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusAccepted, resp.StatusCode, "happy push must return 202")

	// Verify a pending_github_deploys row was inserted.
	var count int
	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pending_github_deploys WHERE connection_id = $1 AND commit_sha = $2`,
		conn.ID, commitSHA,
	).Scan(&count)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1, "a pending_github_deploys row must exist after a happy push")

	// Verify last_commit_sha was bumped.
	var lastSHA string
	err = db.QueryRowContext(ctx,
		`SELECT COALESCE(last_commit_sha,'') FROM app_github_connections WHERE id = $1`, conn.ID,
	).Scan(&lastSHA)
	require.NoError(t, err)
	assert.Equal(t, commitSHA, lastSHA)
}

// ── push rate-limited (cap saturated) → 202 with enqueued:0 ───────────────────

func TestGitHubAppWebhook_Push_RateLimited(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 200299
	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	deploymentUUID := uuid.New()
	_, err = db.Exec(`INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'healthy')`,
		deploymentUUID, teamID, "ghwh-rl-"+deploymentUUID.String()[:8])
	require.NoError(t, err)

	instID64 := installID
	conn, cerr := models.CreateGitHubConnection(ctx, db, models.CreateGitHubConnectionParams{
		AppID: deploymentUUID, TeamID: teamID, GitHubRepo: "owner/rl-repo", Branch: "main",
		WebhookSecret: "placeholder", InstallationID: &instID64,
	})
	require.NoError(t, cerr)

	// Saturate the per-connection hourly cap (githubMaxDeploysPerHour = 10).
	for i := 0; i < 10; i++ {
		_, eerr := models.EnqueueGitHubDeploy(ctx, db, models.EnqueueGitHubDeployParams{
			ConnectionID: conn.ID, AppID: deploymentUUID, CommitSHA: fmt.Sprintf("%040d", i), PusherLogin: "",
		})
		require.NoError(t, eerr)
	}

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	body := pushEventBody("owner/rl-repo", "main", "aabbccddeeff00112233445566778899aabbccdd", installID)
	resp := whibPost(t, app, body, "push", "push-rl-001")
	var out struct {
		Matched  int `json:"matched"`
		Enqueued int `json:"enqueued"`
	}
	whibDecodeJSON(t, resp, &out)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.Equal(t, 1, out.Matched, "the connection matched the push")
	assert.Equal(t, 0, out.Enqueued, "the matched connection was rate-limited → 0 enqueued")
}

// ── push no_connection → 200 ignored ─────────────────────────────────────────

func TestGitHubAppWebhook_Push_NoConnection_Ignored(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 200202

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	// Push for a repo+branch with no matching app_github_connections row.
	body := pushEventBody("owner/no-such-repo", "main", "deadbeef0000000000000000000000000000dead", installID)
	resp := whibPost(t, app, body, "push", "push-noconn-001")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]interface{}
	whibDecodeJSON(t, resp, &out)
	assert.Equal(t, "no_connection", out["reason"], "reason must be no_connection")
}

// ── push no_active_installation → 200 ignored ────────────────────────────────

func TestGitHubAppWebhook_Push_NoActiveInstallation_Ignored(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	// Push whose installation_id has NO github_installations row at all.
	const missingInstallID int64 = 999999999
	body := pushEventBody("owner/whatever", "main", "cafebabe0000000000000000000000000000cafe", missingInstallID)
	resp := whibPost(t, app, body, "push", "push-noinst-001")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]interface{}
	whibDecodeJSON(t, resp, &out)
	assert.Equal(t, "no_active_installation", out["reason"])
}

// ── push when installation is suspended → 200 no_active_installation ─────────

func TestGitHubAppWebhook_Push_SuspendedInstallation_Ignored(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	const installID int64 = 200203

	_, err := models.UpsertGitHubInstallation(ctx, db, installID, teamID, "acme-org")
	require.NoError(t, err)
	require.NoError(t, models.SetGitHubInstallationSuspended(ctx, db, installID, true))

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	body := pushEventBody("owner/repo-suspended", "main", "face00000000000000000000000000000000face", installID)
	resp := whibPost(t, app, body, "push", "push-suspended-001")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out map[string]interface{}
	whibDecodeJSON(t, resp, &out)
	assert.Equal(t, "no_active_installation", out["reason"])
}

// ── delivery dedup (replay) ───────────────────────────────────────────────────

func TestGitHubAppWebhook_DeliveryDedup_Replay(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	// Use a ping event (no DB access) to isolate the dedup logic.
	body := []byte(`{"zen":"Keep it logically awesome.","hook_id":1}`)
	const deliveryID = "dedup-delivery-abc123"

	// First delivery — should process normally (200 pong).
	resp1 := whibPost(t, app, body, "ping", deliveryID)
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	var out1 map[string]interface{}
	whibDecodeJSON(t, resp1, &out1)
	_, isDuplicate1 := out1["duplicate"]
	assert.False(t, isDuplicate1, "first delivery must not be marked duplicate")

	// Second delivery with the same X-GitHub-Delivery → replay.
	resp2 := whibPost(t, app, body, "ping", deliveryID)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	var out2 map[string]interface{}
	whibDecodeJSON(t, resp2, &out2)
	isDup2, _ := out2["duplicate"].(bool)
	assert.True(t, isDup2, "second delivery with same id must be marked duplicate:true")
}

// ── push: connection belongs to a different installation → matched==0 ─────────

func TestGitHubAppWebhook_Push_InstallationMismatch_NoConnection(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ctx := context.Background()
	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	// Installation A — the one that owns the connection.
	const installA int64 = 300301
	_, err := models.UpsertGitHubInstallation(ctx, db, installA, teamA, "acme-org")
	require.NoError(t, err)

	// Installation B — the one that will send the push (different installation).
	const installB int64 = 300302
	_, err = models.UpsertGitHubInstallation(ctx, db, installB, teamB, "other-org")
	require.NoError(t, err)

	// Deploy + connection owned by installA/teamA.
	deployUUID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO deployments (id, team_id, app_id, port, tier, status)
		VALUES ($1, $2, $3, 8080, 'pro', 'healthy')`,
		deployUUID, teamA, "ghwh-mm-"+deployUUID.String()[:8])
	require.NoError(t, err)

	instA64 := installA
	_, cerr := models.CreateGitHubConnection(ctx, db, models.CreateGitHubConnectionParams{
		AppID:          deployUUID,
		TeamID:         teamA,
		GitHubRepo:     "owner/mismatch-repo",
		Branch:         "main",
		WebhookSecret:  "placeholder",
		InstallationID: &instA64,
	})
	require.NoError(t, cerr)

	app, clean := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy", whibEnableWebhook)
	defer clean()

	// Push comes from installB — the connection's InstallationID (installA) won't match.
	body := pushEventBody("owner/mismatch-repo", "main", "1234567890abcdef1234567890abcdef12345678", installB)
	resp := whibPost(t, app, body, "push", "push-mismatch-001")

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]interface{}
	whibDecodeJSON(t, resp, &out)
	assert.Equal(t, "no_connection", out["reason"])
}
