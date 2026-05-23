package handlers_test

// github_deploy_final_test.go — FINAL coverage pass for github_deploy.go.
// Closes the mid-handler DB-error arms (fetch_failed / create_failed /
// delete_failed / enqueue_failed / lookup_failed) plus the requireTeam
// team-lookup-error arm and the githubConnectionToMap optional-field arms.
//
// The DB-error arms use openFaultDB (faultdb_deployasync_test.go): the early
// auth + first lookup queries succeed, then the targeted query errors.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ghFaultApp wires the GitHub-deploy routes against an arbitrary *sql.DB so a
// fault-injecting DB drives the mid-handler 503 arms.
func ghFaultApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		Environment:     "test",
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if e == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			_ = handlers.WriteFiberError(c, code, "internal_error", e.Error())
			return nil
		},
	})
	app.Use(middleware.RequestID())
	gh := handlers.NewGitHubDeployHandler(db, cfg, plans.Default())
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Post("/deployments/:id/github", gh.Connect)
	api.Get("/deployments/:id/github", gh.Get)
	api.Delete("/deployments/:id/github", gh.Disconnect)
	app.Post("/webhooks/github/:webhook_id", gh.Receive)
	return app
}

func ghSeedTeamUserJWT(t *testing.T, db *sql.DB) (teamID, jwt string) {
	t.Helper()
	teamID = testhelpers.MustCreateTeamDB(t, db, "pro")
	email := testhelpers.UniqueEmail(t)
	var userID string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO users (team_id, email) VALUES ($1::uuid, $2) RETURNING id::text`,
		teamID, email).Scan(&userID))
	return teamID, testhelpers.MustSignSessionJWT(t, userID, teamID, email)
}

func ghPost(t *testing.T, app *fiber.App, path, jwt, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}
	req.Header.Set("X-Forwarded-For", "10.99.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	return resp
}

func ghErr(t *testing.T, resp *http.Response) string {
	t.Helper()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	if s, ok := m["error"].(string); ok {
		return s
	}
	return ""
}

// ── Connect DB-error arms ────────────────────────────────────────────────────

// Connect: GetDeploymentByAppID errors → fetch_failed (github_deploy.go:161).
// Sequence: requireTeam team lookup (1) succeeds, GetDeploymentByAppID (2)
// errors. failAfter=1.
func TestGHFinal_Connect_DeploymentFetch_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghf")

	faultDB := openFaultDB(t, 1)
	app := ghFaultApp(t, faultDB)
	resp := ghPost(t, app, "/api/v1/deployments/"+appID+"/github", jwt, `{"repo":"a/b","branch":"main"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// Connect: CreateGitHubConnection errors with a non-duplicate error →
// create_failed (github_deploy.go:228). team(1) + deployment(2) succeed, the
// INSERT (3) errors. failAfter=2.
func TestGHFinal_Connect_CreateFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghc")

	faultDB := openFaultDB(t, 2)
	app := ghFaultApp(t, faultDB)
	resp := ghPost(t, app, "/api/v1/deployments/"+appID+"/github", jwt, `{"repo":"a/b","branch":"main"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "create_failed", ghErr(t, resp))
}

// ── Get DB-error arms ────────────────────────────────────────────────────────

// Get: GetDeploymentByAppID errors → fetch_failed (github_deploy.go:276).
func TestGHFinal_Get_DeploymentFetch_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghg")

	faultDB := openFaultDB(t, 1)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// Get: deployment ok, GetGitHubConnectionByAppID errors → fetch_failed
// (github_deploy.go:294). team(1) + deployment(2) succeed, connection(3) errors.
func TestGHFinal_Get_ConnectionFetch_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghg2")

	faultDB := openFaultDB(t, 2)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// ── Disconnect DB-error arms ─────────────────────────────────────────────────

// Disconnect: deployment fetch errors → fetch_failed (github_deploy.go:324).
func TestGHFinal_Disconnect_DeploymentFetch_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghd")

	faultDB := openFaultDB(t, 1)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// Disconnect: connection lookup errors → fetch_failed (github_deploy.go:339).
func TestGHFinal_Disconnect_ConnectionFetch_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghd2")

	faultDB := openFaultDB(t, 2)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// Disconnect: connection EXISTS, DeleteGitHubConnectionByAppID errors →
// delete_failed (github_deploy.go:343). team(1) + deployment(2) +
// connection-read(3) succeed, DELETE(4) errors. We seed a real connection on
// the pooled DB first.
func TestGHFinal_Disconnect_DeleteFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	// Build a normal app to create the connection row.
	normalApp, cleanApp := ghTestApp(t, seedDB, rdb)
	defer cleanApp()
	appID := ghSeedDeployment(t, seedDB, teamID, "ghdf")
	ghConnect(t, normalApp, jwt, appID)

	faultDB := openFaultDB(t, 3)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "delete_failed", ghErr(t, resp))
}

// ── Receive DB-error + crypto arms ───────────────────────────────────────────

// Receive: GetGitHubConnectionByID errors → fetch_failed (github_deploy.go:408).
// failAfter=0 → the connection lookup (first DB call in Receive) errors.
func TestGHFinal_Receive_LookupFailed_503(t *testing.T) {
	faultDB := openFaultDB(t, 0)
	app := ghFaultApp(t, faultDB)
	connID := uuid.New()
	resp := ghPost(t, app, "/webhooks/github/"+connID.String(), "", `{}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "fetch_failed", ghErr(t, resp))
}

// Receive: enqueue errors (non-rate-limit) → enqueue_failed
// (github_deploy.go:540). A valid signed push event whose connection exists on
// the pooled DB; the fault DB passes the connection-read then fails the
// count/enqueue. We seed the connection on a normal DB and recover its id +
// secret, then drive Receive through the fault DB.
func TestGHFinal_Receive_EnqueueFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	normalApp, cleanApp := ghTestApp(t, seedDB, rdb)
	defer cleanApp()
	appID := ghSeedDeployment(t, seedDB, teamID, "ghre")

	connID, secret := ghConnectAndCapture(t, normalApp, jwt, appID)

	// Build a signed push body.
	body := `{"ref":"refs/heads/main","after":"deadbeefcafe1234567890abcdef000011112222","before":"0","pusher":{"name":"octo"}}`
	sig := ghSign(secret, body)

	faultDB := openFaultDB(t, 1) // connection-read(1) ok, count/enqueue(2) errors
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github/"+connID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("X-Hub-Signature-256", sig)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "enqueue_failed", ghErr(t, resp))
}

// Receive: decrypt failure when the stored secret can't be decrypted with the
// configured key → decrypt_failed (github_deploy.go:421). We seed a connection
// row whose webhook_secret is garbage ciphertext via direct SQL.
func TestGHFinal_Receive_DecryptFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID, _ := ghSeedTeamUserJWT(t, seedDB)
	appID := ghSeedDeployment(t, seedDB, teamID, "ghdec")
	var deployID, connID string
	require.NoError(t, seedDB.QueryRowContext(context.Background(),
		`SELECT id::text FROM deployments WHERE app_id=$1`, appID).Scan(&deployID))
	require.NoError(t, seedDB.QueryRowContext(context.Background(), `
		INSERT INTO app_github_connections (app_id, team_id, github_repo, branch, webhook_secret)
		VALUES ($1::uuid, $2::uuid, 'a/b', 'main', 'not-valid-ciphertext')
		RETURNING id::text`, deployID, teamID).Scan(&connID))

	app := ghFaultApp(t, seedDB) // normal DB; decrypt is what fails
	resp := ghPost(t, app, "/webhooks/github/"+connID, "", `{}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "decrypt_failed", ghErr(t, resp))
}

// ── requireTeam team-lookup error ────────────────────────────────────────────

// requireTeam: GetTeamByID errors → team_lookup_failed (github_deploy.go:613).
// failAfter=0 — the team lookup is the first DB call (RequireAuth is JWT-only).
func TestGHFinal_RequireTeam_LookupFailed_503(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	_, jwt := ghSeedTeamUserJWT(t, seedDB)

	faultDB := openFaultDB(t, 0)
	app := ghFaultApp(t, faultDB)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/anyid/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, "team_lookup_failed", ghErr(t, resp))
}

// requireTeam: JWT tid is not a UUID → invalid_team (github_deploy.go:608).
func TestGHFinal_RequireTeam_BadTeamID_400(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app := ghFaultApp(t, seedDB)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), "not-a-uuid", testhelpers.UniqueEmail(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/x/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_team", ghErr(t, resp))
}

// ── githubConnectionToMap optional-field arms ────────────────────────────────

// A connection with last_deploy_at + last_commit_sha + installation_id set →
// Get renders all three optional fields (github_deploy.go:641,644,647).
func TestGHFinal_Get_ConnectionWithOptionalFields(t *testing.T) {
	seedDB, clean := testhelpers.SetupTestDB(t)
	defer clean()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID, jwt := ghSeedTeamUserJWT(t, seedDB)
	app, cleanApp := ghTestApp(t, seedDB, rdb)
	defer cleanApp()
	appID := ghSeedDeployment(t, seedDB, teamID, "ghopt")
	connID, _ := ghConnectAndCapture(t, app, jwt, appID)

	// Set the optional columns directly.
	_, err := seedDB.ExecContext(context.Background(), `
		UPDATE app_github_connections
		SET last_deploy_at = now(), last_commit_sha = 'abc123', installation_id = 4242
		WHERE id = $1::uuid`, connID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+appID+"/github", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	conn, _ := m["connection"].(map[string]any)
	require.NotNil(t, conn)
	assert.Equal(t, "abc123", conn["last_commit_sha"])
	assert.Equal(t, float64(4242), conn["installation_id"])
	assert.NotNil(t, conn["last_deploy_at"])
}

// ── helpers ──────────────────────────────────────────────────────────────────

// ghConnectAndCapture runs Connect and returns the connection_id + plaintext
// webhook_secret from the 201 response body.
func ghConnectAndCapture(t *testing.T, app *fiber.App, jwt, appID string) (connID, secret string) {
	t.Helper()
	resp := ghPost(t, app, "/api/v1/deployments/"+appID+"/github", jwt, `{"repo":"octocat/hello-world","branch":"main"}`)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var m map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
	conn, _ := m["connection"].(map[string]any)
	require.NotNil(t, conn)
	connID, _ = conn["id"].(string)
	secret, _ = m["webhook_secret"].(string)
	require.NotEmpty(t, connID)
	require.NotEmpty(t, secret)
	return connID, secret
}

// ghSign builds the "sha256=<hex>" X-Hub-Signature-256 header value.
func ghSign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

var _ = crypto.ParseAESKey
var _ redis.Client
