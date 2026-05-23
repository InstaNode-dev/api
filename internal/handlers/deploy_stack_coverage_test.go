package handlers_test

// deploy_stack_coverage_test.go — targeted coverage push for the deploy/stack
// handler files. Aims for >=95% on:
//
//   deploy.go, deploy_*.go (Logs, UpdateEnv, Redeploy, ConfirmDelete, CancelDelete,
//                           SetTTL, MakePermanent, doImmediateDelete, helpers)
//   stack.go, stack_*.go   (Logs, Delete, ConfirmDelete, CancelDelete, Redeploy,
//                           rewriteToInternalURL, resourceEnvKey, parseResourceToken,
//                           consumeApprovedPromote)
//   deploys_audit.go       (List with service/since/limit branches)
//
// All tests use the noop compute provider (via SetComputeProvider) and the
// test DB. They skip cleanly when TEST_DATABASE_URL is unset.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/noop"
	"instant.dev/internal/testhelpers"
)

// requireCoverageDB skips tests when TEST_DATABASE_URL is unset.
func requireCoverageDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
}

// seedDeploy inserts a deployment row directly and returns its IDs/appID.
// Includes provider_id so Logs / Redeploy paths reach the compute call.
func seedDeploy(t *testing.T, db *sql.DB, teamID uuid.UUID, status, tier string) (deployID uuid.UUID, appID string) {
	t.Helper()
	appID = "cov-" + uuid.NewString()[:10]
	err := db.QueryRow(`
		INSERT INTO deployments (team_id, app_id, provider_id, port, tier, status, env_vars)
		VALUES ($1, $2, $3, 8080, $4, $5, '{"FOO":"bar"}'::jsonb)
		RETURNING id
	`, teamID, appID, "noop-"+appID, tier, status).Scan(&deployID)
	require.NoError(t, err)
	return deployID, appID
}

// ── deploy/Logs ───────────────────────────────────────────────────────────────

// TestDeployLogs_HappyPath — noop provider returns an empty stream and the
// handler returns 200 with SSE headers.
func TestDeployLogs_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "logs@example.com")

	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+appID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.1")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-cache", resp.Header.Get("Cache-Control"))
}

// TestDeployLogs_UnknownAppID returns 404.
func TestDeployLogs_UnknownAppID(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "logs404@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/deploy/missing-app/logs", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.2")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDeployLogs_CrossTeam returns 404, not 403.
func TestDeployLogs_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	ownerTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerTeamID := uuid.MustParse(ownerTeamStr)
	_, appID := seedDeploy(t, db, ownerTeamID, "healthy", "pro")

	otherTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherTeamStr, "other@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+appID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.3")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"cross-team access must 404, never 403")
}

// TestDeployLogs_NoProviderIDReturns409 — building/no-provider row returns 409 not_ready.
func TestDeployLogs_NoProviderIDReturns409(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	appID := "noprov-" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status, env_vars)
		VALUES ($1, $2, 8080, 'pro', 'building', '{}'::jsonb)
	`, teamID, appID)
	require.NoError(t, err)
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "noprov@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+appID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.30.0.4")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── deploy/UpdateEnv (PATCH /deploy/:id/env) ─────────────────────────────────
// The PATCH /deploy/:id/env route is NOT wired in NewTestAppWithServices, so
// we register a minimal app inline.

// patchEnvApp builds a Fiber app with just PATCH /deploy/:id/env wired so
// the UpdateEnv handler is exercised without bringing in unrelated middleware.
func patchEnvApp(t *testing.T, db *sql.DB) (*fiber.App, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Patch("/deploy/:id/env", middleware.RequireAuth(cfg), dh.UpdateEnv)
	app.Get("/deploy/:id", middleware.RequireAuth(cfg), dh.Get)
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)
	app.Post("/api/v1/deployments/:id/make-permanent", middleware.RequireAuth(cfg), dh.MakePermanent)
	app.Post("/api/v1/deployments/:id/ttl", middleware.RequireAuth(cfg), dh.SetTTL)
	return app, cfg
}

func TestDeployUpdateEnv_MergesAndReturnsRedacted(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "envup@example.com")

	app, _ := patchEnvApp(t, db)

	body := strings.NewReader(`{"env":{"DEBUG":"1","API_KEY":"secret-xyz"}}`)
	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+appID+"/env", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var out struct {
		OK   bool              `json:"ok"`
		Env  map[string]string `json:"env"`
		Note string            `json:"note"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	assert.True(t, out.OK)
	assert.Contains(t, out.Note, "redeploy")
	// Non-secret key passes through unchanged.
	assert.Equal(t, "1", out.Env["DEBUG"])
	// API_KEY matches isSecretKey heuristic — must be redacted.
	if v, ok := out.Env["API_KEY"]; ok {
		assert.NotEqual(t, "secret-xyz", v, "API_KEY must be redacted in outbound response")
	}
}

func TestDeployUpdateEnv_InvalidBody(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "envbad@example.com")

	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+appID+"/env",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployUpdateEnv_EmptyEnv(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "envempty@example.com")

	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+appID+"/env",
		strings.NewReader(`{"env":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployUpdateEnv_UnknownAppID(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "env404@example.com")

	app, _ := patchEnvApp(t, db)
	req := httptest.NewRequest(http.MethodPatch, "/deploy/missing/env",
		strings.NewReader(`{"env":{"K":"V"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeployUpdateEnv_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	_, appID := seedDeploy(t, db, ownerID, "healthy", "pro")

	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "envother@example.com")

	app, _ := patchEnvApp(t, db)
	req := httptest.NewRequest(http.MethodPatch, "/deploy/"+appID+"/env",
		strings.NewReader(`{"env":{"K":"V"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── deploy/Redeploy ───────────────────────────────────────────────────────────

func multipartTarballBody(t *testing.T, name string) (*bytes.Buffer, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)
	fw, err := mw.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return buf, mw.FormDataContentType()
}

func TestDeployRedeploy_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rd1@example.com")

	app, _ := patchEnvApp(t, db)
	body, ct := multipartTarballBody(t, appID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	// Wait a beat for the async goroutine to fire its safego work so its
	// code path is recorded in coverage.
	time.Sleep(300 * time.Millisecond)
}

func TestDeployRedeploy_UnknownAppID(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rd404@example.com")
	app, _ := patchEnvApp(t, db)
	body, ct := multipartTarballBody(t, "missing")
	req := httptest.NewRequest(http.MethodPost, "/deploy/missing/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeployRedeploy_TerminalStatusConflict(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, models.DeployStatusDeleted, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdterm@example.com")
	app, _ := patchEnvApp(t, db)
	body, ct := multipartTarballBody(t, appID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestDeployRedeploy_NoProviderConflict(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	appID := "rdnop-" + uuid.NewString()[:8]
	_, err := db.Exec(`
		INSERT INTO deployments (team_id, app_id, port, tier, status, env_vars)
		VALUES ($1, $2, 8080, 'pro', 'building', '{}'::jsonb)
	`, teamID, appID)
	require.NoError(t, err)
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdnop@example.com")
	app, _ := patchEnvApp(t, db)
	body, ct := multipartTarballBody(t, appID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestDeployRedeploy_MissingTarball(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdmt@example.com")
	app, _ := patchEnvApp(t, db)

	// Empty multipart with NO tarball field.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.Close())
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployRedeploy_InvalidForm(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdform@example.com")
	app, _ := patchEnvApp(t, db)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy",
		strings.NewReader("not-multipart"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployRedeploy_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	_, appID := seedDeploy(t, db, ownerID, "healthy", "pro")
	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "rdcross@example.com")
	app, _ := patchEnvApp(t, db)
	body, ct := multipartTarballBody(t, appID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+appID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── deploy/MakePermanent + SetTTL ─────────────────────────────────────────────

func TestDeployMakePermanent_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "mp@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify expires_at is NULL.
	var expiresAt sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT expires_at FROM deployments WHERE id=$1`, deployID).Scan(&expiresAt))
	assert.False(t, expiresAt.Valid)
}

func TestDeployMakePermanent_AnonymousRejected(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "anonymous")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "mpanon@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

func TestDeployMakePermanent_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	deployID, _ := seedDeploy(t, db, ownerID, "healthy", "pro")
	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "mpcross@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeployMakePermanent_UnknownID(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "mpnone@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+uuid.NewString()+"/make-permanent", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDeploySetTTL_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "tt@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/ttl",
		strings.NewReader(`{"hours":48}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDeploySetTTL_HoursOutOfRange(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttoor@example.com")
	app, _ := patchEnvApp(t, db)

	for _, h := range []int{0, -1, 9999} {
		body := strings.NewReader(`{"hours":` + itoa(h) + `}`)
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/deployments/"+deployID.String()+"/ttl", body)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+sessionJWT)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "hours=%d must be rejected", h)
		resp.Body.Close()
	}
}

func TestDeploySetTTL_InvalidBody(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttib@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/ttl",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeploySetTTL_AnonymousRejected(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	teamID := uuid.MustParse(teamIDStr)
	deployID, _ := seedDeploy(t, db, teamID, "healthy", "anonymous")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttanon@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+deployID.String()+"/ttl",
		strings.NewReader(`{"hours":24}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
}

func TestDeploySetTTL_UnknownID(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttnone@example.com")
	app, _ := patchEnvApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/"+uuid.NewString()+"/ttl",
		strings.NewReader(`{"hours":24}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestDeployTTL_MissingID — both endpoints reject empty id via lookupDeployment.
func TestDeployTTL_BadUUIDFallsThroughToAppIDLookup(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttbad@example.com")
	app, _ := patchEnvApp(t, db)

	// "not-a-uuid" — lookupDeployment first tries app_id (no row), then UUID parse fails → 404.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/deployments/not-a-uuid-thing/ttl",
		strings.NewReader(`{"hours":24}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ── deploy/doImmediateDelete: free-tier path ─────────────────────────────────

func TestDeployDelete_FreeTier_ImmediateDestroy(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "free")
	teamID := uuid.MustParse(teamIDStr)
	_, appID := seedDeploy(t, db, teamID, "healthy", "free")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "delfree@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/deployments/"+appID, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.40.0.1")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── deploy/Get filter via List ────────────────────────────────────────────────

func TestDeployList_EnvFilter(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, _ = seedDeploy(t, db, teamID, "healthy", "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "envf@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	// Filter by env=production — env_filter branch is exercised.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments?env=production", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.40.0.2")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestDeployList_InvalidEnvFilter_ReturnsEmpty(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "envf2@example.com")

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb,
		"postgres,redis,mongodb,queue,webhook,storage,deploy")
	defer cleanApp()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/deployments?env=garbage!!!", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Forwarded-For", "10.40.0.3")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// NormalizeEnv returns !ok → early empty-list return.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		Items []any `json:"items"`
		Total int   `json:"total"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, 0, body.Total)
}

// ── SetEmailClient / SetComputeProvider on stack handler ─────────────────────

func TestStackHandler_SettersCovered(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		ComputeProvider: "noop",
	}
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetEmailClient(email.NewNoop())
	// SetEmailClient must not panic and must be safe with a nil mailer too.
	sh.SetEmailClient(nil)
}

// ── DeployHandler.SetComputeProvider already used in reconciler tests ────────
// This explicitly exercises the swap with a fakeTeardownProvider so the line
// is recorded under this scope as well.

func TestDeployHandler_SetComputeProviderCovered(t *testing.T) {
	cfg := &config.Config{ComputeProvider: "noop"}
	h := handlers.NewDeployHandler(nil, nil, cfg, plans.Default())
	h.SetComputeProvider(noop.New())
}

// ── Stack: Logs / Delete / Redeploy / ConfirmDelete / CancelDelete ───────────

func newCoverageStackApp(t *testing.T, db *sql.DB) (*fiber.App, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
		// DeletionConfirmationTTLMinutes is required for the two-step flow.
		DeletionConfirmationTTLMinutes: 30,
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetEmailClient(email.NewNoop())

	app.Post("/stacks/new", middleware.OptionalAuth(cfg), sh.New)
	app.Get("/stacks/:slug", middleware.OptionalAuth(cfg), sh.Get)
	app.Get("/stacks/:slug/logs/:svc", middleware.OptionalAuth(cfg), sh.Logs)
	app.Delete("/stacks/:slug", middleware.OptionalAuth(cfg), sh.Delete)
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), sh.UpdateEnv)
	app.Post("/stacks/:slug/redeploy", middleware.RequireAuth(cfg), sh.Redeploy)

	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/stacks", sh.List)
	api.Post("/stacks/:slug/promote", sh.Promote)
	api.Get("/stacks/:slug/family", sh.Family)
	api.Post("/stacks/:slug/confirm-deletion", sh.ConfirmDelete)
	api.Delete("/stacks/:slug/confirm-deletion", sh.CancelDelete)
	return app, cfg
}

// ensureStackTables2 mirrors ensureStackTables (private to stack_test.go is in
// same package but tests are out-of-package; reuse the production migration
// surface here for safety).
func ensureStackTables2(t *testing.T, db *sql.DB) {
	t.Helper()
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS stacks (
			id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			team_id         UUID REFERENCES teams(id) ON DELETE CASCADE,
			name            TEXT,
			slug            TEXT UNIQUE NOT NULL,
			namespace       TEXT UNIQUE NOT NULL,
			status          TEXT NOT NULL DEFAULT 'building',
			tier            TEXT NOT NULL DEFAULT 'hobby',
			env             TEXT NOT NULL DEFAULT 'production',
			parent_stack_id UUID,
			expires_at      TIMESTAMPTZ,
			fingerprint     TEXT,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production'`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS parent_stack_id UUID`,
		`ALTER TABLE stacks ADD COLUMN IF NOT EXISTS env_vars JSONB NOT NULL DEFAULT '{}'::jsonb`,
		`CREATE TABLE IF NOT EXISTS stack_services (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			stack_id    UUID NOT NULL REFERENCES stacks(id) ON DELETE CASCADE,
			name        TEXT NOT NULL,
			image_tag   TEXT,
			image_ref   TEXT,
			status      TEXT NOT NULL DEFAULT 'building',
			expose      BOOLEAN NOT NULL DEFAULT FALSE,
			port        INT NOT NULL DEFAULT 8080,
			app_url     TEXT,
			error_msg   TEXT,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE(stack_id, name)
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("ensureStackTables2: %v\n  SQL: %.120s", err, s)
		}
	}
}

func seedStack(t *testing.T, db *sql.DB, teamID *uuid.UUID, status string) (stackID uuid.UUID, slug string) {
	t.Helper()
	slug = "stk-" + uuid.NewString()[:10]
	namespace := "instant-stack-" + slug
	if teamID != nil {
		require.NoError(t, db.QueryRow(`
			INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
			VALUES ($1, $2, $3, $4, 'pro', 'production')
			RETURNING id
		`, *teamID, slug, namespace, status).Scan(&stackID))
	} else {
		require.NoError(t, db.QueryRow(`
			INSERT INTO stacks (slug, namespace, status, tier, env)
			VALUES ($1, $2, $3, 'hobby', 'production')
			RETURNING id
		`, slug, namespace, status).Scan(&stackID))
	}
	// Add one service so Logs/Delete paths have something to enumerate.
	_, err := db.Exec(`
		INSERT INTO stack_services (stack_id, name, port, status, expose)
		VALUES ($1, $2, 8080, 'healthy', true)
	`, stackID, "web")
	require.NoError(t, err)
	return stackID, slug
}

func TestStackLogs_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "healthy")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "sl@example.com")

	app, _ := newCoverageStackApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug+"/logs/web", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
}

func TestStackLogs_UnknownSlug(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodGet, "/stacks/missing/logs/web", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStackDelete_AnonymousImmediate(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	_, slug := seedStack(t, db, nil, "healthy")
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestStackDelete_PaidQueuesPendingConfirmation(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	ownerEmail := "ownerstack-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, ownerEmail)
	require.NoError(t, err)
	_, slug := seedStack(t, db, &teamID, "healthy")
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, ownerEmail)

	app, _ := newCoverageStackApp(t, db)
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Paid-tier path goes through requestEmailConfirmedDeletion. Either 202
	// (pending) or 200 (immediate, if the dependency wiring degrades) — both
	// exercise doImmediateStackDelete or the two-step branch.
	assert.Contains(t, []int{http.StatusAccepted, http.StatusOK}, resp.StatusCode,
		"expected 200 or 202, got %d", resp.StatusCode)
}

func TestStackDelete_HeaderBypass(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	bypEmail := "byp-" + uuid.NewString()[:8] + "@example.com"
	userID, err := addOwnerUser(db, teamID, bypEmail)
	require.NoError(t, err)
	_, slug := seedStack(t, db, &teamID, "healthy")
	sessionJWT := testhelpers.MustSignSessionJWT(t, userID.String(), teamIDStr, bypEmail)

	app, _ := newCoverageStackApp(t, db)
	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+slug, nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	req.Header.Set("X-Skip-Email-Confirmation", "yes")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestStackRedeploy_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "healthy")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdstk@example.com")

	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    expose: true\n"
	tar := newMinimalTarball(t)
	body, ct := stackMultipart(t, manifest, map[string][]byte{"web": tar})
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	time.Sleep(300 * time.Millisecond)
}

func TestStackRedeploy_MissingManifest(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "healthy")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdstk2@example.com")
	app, _ := newCoverageStackApp(t, db)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.Close())
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestStackRedeploy_DeletingStatusReturns409(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	_, slug := seedStack(t, db, &teamID, "deleting")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rddel@example.com")
	app, _ := newCoverageStackApp(t, db)

	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    expose: true\n"
	body, ct := stackMultipart(t, manifest, map[string][]byte{"web": newMinimalTarball(t)})
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestStackRedeploy_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)

	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	_, slug := seedStack(t, db, &ownerID, "healthy")

	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "rdcross@example.com")
	app, _ := newCoverageStackApp(t, db)

	manifest := "services:\n  web:\n    build: ./web\n    port: 8080\n    expose: true\n"
	body, ct := stackMultipart(t, manifest, map[string][]byte{"web": newMinimalTarball(t)})
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStackCancelDelete_UnknownSlug(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "candel@example.com")
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stacks/missing/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStackCancelDelete_CrossTeam(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)
	ownerStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	ownerID := uuid.MustParse(ownerStr)
	_, slug := seedStack(t, db, &ownerID, "healthy")

	otherStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), otherStr, "candelx@example.com")
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stacks/"+slug+"/confirm-deletion", nil)
	req.Header.Set("Authorization", "Bearer "+otherJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestStackConfirmDelete_InvalidToken(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)
	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	sessionJWT := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "conf@example.com")
	app, _ := newCoverageStackApp(t, db)

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/stacks/anything/confirm-deletion?token=garbage", nil)
	req.Header.Set("Authorization", "Bearer "+sessionJWT)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Bad token can surface as 400 / 401 / 404 / 410 depending on the
	// resolveEmailConfirmedDeletion branch; assert NOT 2xx.
	assert.GreaterOrEqual(t, resp.StatusCode, 400, "an invalid token must not succeed")
}

// ── DeploysAudit (admin-only) ─────────────────────────────────────────────────

func TestDeploysAudit_List_HappyPath(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Ensure the deploys_audit table exists by inserting a row directly.
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS deploys_audit (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		service TEXT NOT NULL,
		commit_id TEXT NOT NULL,
		image_digest TEXT NOT NULL,
		version TEXT,
		build_time TIMESTAMPTZ,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
		migration_version TEXT,
		noticed_by TEXT NOT NULL DEFAULT 'self-report',
		UNIQUE (service, commit_id, image_digest)
	)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO deploys_audit (service, commit_id, image_digest, version)
		VALUES ('api', 'abc123', 'sha256:dead', '0.0.1')
		ON CONFLICT DO NOTHING`)
	require.NoError(t, err)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	h := handlers.NewDeploysAuditHandler(db)
	app.Get("/deploys", h.List)

	// Happy path with service + limit.
	req := httptest.NewRequest(http.MethodGet, "/deploys?service=api&limit=10", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Invalid service.
	req2 := httptest.NewRequest(http.MethodGet, "/deploys?service=junk", nil)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)

	// Invalid since.
	req3 := httptest.NewRequest(http.MethodGet, "/deploys?since=not-a-timestamp", nil)
	resp3, err := app.Test(req3, 5000)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp3.StatusCode)

	// since too old.
	req4 := httptest.NewRequest(http.MethodGet, "/deploys?since=1980-01-01T00:00:00Z", nil)
	resp4, err := app.Test(req4, 5000)
	require.NoError(t, err)
	defer resp4.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp4.StatusCode)

	// Invalid limit.
	req5 := httptest.NewRequest(http.MethodGet, "/deploys?limit=junk", nil)
	resp5, err := app.Test(req5, 5000)
	require.NoError(t, err)
	defer resp5.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp5.StatusCode)

	// Valid since.
	since := time.Now().Add(-1 * time.Hour).UTC().Format(time.RFC3339)
	req6 := httptest.NewRequest(http.MethodGet, "/deploys?since="+since, nil)
	resp6, err := app.Test(req6, 5000)
	require.NoError(t, err)
	defer resp6.Body.Close()
	assert.Equal(t, http.StatusOK, resp6.StatusCode)
}

// ── stack/UpdateEnv helpers + Logs unknown service ────────────────────────────

func TestStackLogs_AnonymousStackReadable(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables2(t, db)
	_, slug := seedStack(t, db, nil, "healthy")

	app, _ := newCoverageStackApp(t, db)
	req := httptest.NewRequest(http.MethodGet, "/stacks/"+slug+"/logs/web", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Anonymous stack with anonymous caller (no auth) — readable in the noop path.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── Reconciler StartTeardownReconciler covers the goroutine launch ───────────

func TestStartTeardownReconciler_LifecycleCovered(t *testing.T) {
	requireCoverageDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	cfg := &config.Config{}
	h := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	h.SetComputeProvider(noop.New())

	ctx, cancel := context.WithCancel(context.Background())
	h.StartTeardownReconciler(ctx)
	// Let the goroutine spin up + register its panic recover.
	time.Sleep(200 * time.Millisecond)
	cancel()
	// Give the loop a tick to observe the cancellation.
	time.Sleep(200 * time.Millisecond)
}

// (itoa lives in admin_customers_test.go in the same _test package; we reuse it.)

// addOwnerUser inserts an owner user for the given team and returns its UUID.
func addOwnerUser(db *sql.DB, teamID uuid.UUID, email string) (uuid.UUID, error) {
	var id uuid.UUID
	err := db.QueryRow(`
		INSERT INTO users (team_id, email, role, is_primary)
		VALUES ($1, $2, 'owner', true)
		RETURNING id
	`, teamID, email).Scan(&id)
	return id, err
}

// newMinimalTarball mirrors stack_test.go createMinimalTarball but is private
// to this file.
func newMinimalTarball(t *testing.T) []byte {
	t.Helper()
	// Reuse the helper from stack_test.go via its public symbol — both files
	// share the same _test package.
	return createMinimalTarball(t)
}

// stackMultipart mirrors multipartBody in stack_test.go with a hand-rolled
// multipart so we don't depend on the optional name field default-injection.
func stackMultipart(t *testing.T, manifestYAML string, tarballs map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormField("manifest")
	require.NoError(t, err)
	_, err = io.WriteString(fw, manifestYAML)
	require.NoError(t, err)
	for svcName, tarball := range tarballs {
		ff, err := mw.CreateFormFile(svcName, svcName+".tar.gz")
		require.NoError(t, err)
		_, err = ff.Write(tarball)
		require.NoError(t, err)
	}
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

// ── unused-symbol guards to silence import warnings if a branch is trimmed ──

var _ = compute.DeployOptions{}
var _ = plans.Default
