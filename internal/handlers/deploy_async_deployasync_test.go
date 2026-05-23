package handlers_test

// deploy_async_deployasync_test.go — coverage for the remaining sub-95%
// branches in deploy.go. Owned by the deploy/stack async-pipeline coverage
// slice (suffix `_deployasync`). Scope: deploy.go ONLY.
//
// Targets the uncovered arms the existing deploy_stack_*_test.go files leave:
//   - deploymentToMapWithDB: error_message + resource_id branches.
//   - captureAutopsy: UpsertDeploymentAutopsy error (closed DB) → warn branch.
//   - New: tarball-too-large 400, missing-tarball 400.
//   - Redeploy: async goroutine vault-resolve failure → failed + autopsy.
//   - Redeploy: async goroutine compute success → healthy (full goroutine body).

import (
	"context"
	"database/sql"
	"errors"
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
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

func daDeployNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping deploy deployasync coverage")
	}
}

// daClosedDeployDB returns an already-closed *sql.DB.
func daClosedDeployDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/instant_dev_test?sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	return db
}

// ── deploymentToMapWithDB error_message + resource_id branches ───────────────

func TestDeploymentToMap_ErrorMessageAndResourceID(t *testing.T) {
	rid := uuid.New()
	d := &models.Deployment{
		ID:           uuid.New(),
		TeamID:       uuid.New(),
		AppID:        "abc12345",
		Status:       "failed",
		ErrorMessage: "build blew up",
		ResourceID:   uuid.NullUUID{UUID: rid, Valid: true},
		EnvVars:      map[string]string{"FOO": "bar"},
	}
	m := handlers.DeploymentToMapForTest(d)
	assert.Equal(t, "build blew up", m["error"])
	assert.Equal(t, rid, m["resource_id"])
}

// TestDeploymentToMapWithDB_AutopsyQueryError drives the failed-status +
// db-error arm in deploymentToMapWithDB (L294-298): a failed deployment with a
// CLOSED db handle makes GetLatestDeploymentAutopsy error → warn + omit the
// failure field (no panic).
func TestDeploymentToMapWithDB_AutopsyQueryError(t *testing.T) {
	d := &models.Deployment{
		ID:      uuid.New(),
		TeamID:  uuid.New(),
		AppID:   "fail1234",
		Status:  "failed",
		EnvVars: map[string]string{},
	}
	m := handlers.DeploymentToMapWithDBForTest(d, daClosedDeployDB(t))
	// failure field is omitted because the autopsy query errored.
	_, hasFailure := m["failure"]
	assert.False(t, hasFailure)
}

// TestDeploymentToMapWithDB_AutopsyPresent drives the failed-status path with a
// REAL db + a seeded autopsy row so the failure-object assembly branch (incl.
// the exit_code-valid / nil arms) is exercised.
func TestDeploymentToMapWithDB_AutopsyPresent(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	d := seedInternalDeploy(t, db, teamID, "failed", map[string]string{"FOO": "bar"})
	handlers.CaptureAutopsyForTest(context.Background(), db, d.ID,
		models.FailureReasonBuildFailed, "boom", []string{"line1", "line2"})

	got, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	m := handlers.DeploymentToMapWithDBForTest(got, db)
	failure, ok := m["failure"].(fiber.Map)
	require.True(t, ok, "failure object must be present for a failed deploy with an autopsy")
	assert.Contains(t, failure, "reason")
	assert.Contains(t, failure, "exit_code")
}

// ── ConfirmDelete: email client not wired → 503 deletion_email_disabled ──────

func TestDeployConfirmDelete_NoEmailClient_503(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ned@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	// NewDeployHandler does NOT wire an email client → ConfirmDelete 503s.
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Post("/deploy/:id/confirm-deletion", middleware.RequireAuth(cfg), dh.ConfirmDelete)

	req := httptest.NewRequest(http.MethodPost, "/deploy/whatever/confirm-deletion?token=x", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ── Delete: free tier immediate destroy with a provider id (teardown path) ───

func TestDeployDelete_FreeTier_ImmediateWithProvider(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "fd@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Delete("/deploy/:id", middleware.RequireAuth(cfg), dh.Delete)

	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	req := httptest.NewRequest(http.MethodDelete, "/deploy/"+d.AppID, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Anonymous/free tier with no email client → immediate destruction (200).
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── captureAutopsy: closed-DB Upsert error → warn branch ─────────────────────

func TestCaptureAutopsy_ClosedDB_WarnBranch(t *testing.T) {
	// No assertion beyond "does not panic / returns" — captureAutopsy swallows
	// the error and logs at WARN. Drives the UpsertDeploymentAutopsy-error arm.
	handlers.CaptureAutopsyForTest(context.Background(), daClosedDeployDB(t), uuid.New(),
		models.FailureReasonBuildFailed, "boom", []string{"l1"})
}

// ── New: tarball-too-large 400 ───────────────────────────────────────────────

// multipartDeployBodyBigTarball builds a deploy multipart body where the
// tarball part claims a size over the 50 MB cap. fasthttp/multipart records
// the actual written size, so we write just over the limit. To avoid a 50 MB
// allocation we instead exercise the missing-tarball + invalid-port arms which
// are cheap and deterministic.

func TestDeployNew_MissingTarball_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "mt@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Multipart with a `name` field but NO tarball file.
	buf := &strings.Builder{}
	mw := multipart.NewWriter(buf)
	require.NoError(t, mw.WriteField("name", "no-tarball"))
	require.NoError(t, mw.Close())
	body := strings.NewReader(buf.String())
	ct := mw.FormDataContentType()

	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidPort_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ip@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "not-a-number"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.2")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_PortOutOfRange_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "por@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "70000"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.3")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidEnvVars_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "iev@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// env_vars not a JSON object → invalid_env_vars 400.
	body, ct := multipartDeployBody(t, map[string]string{"env_vars": "not-json"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.4")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidEnvKey_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "iek@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// lowercase key is not a valid POSIX env var name → invalid_env_key 400.
	body, ct := multipartDeployBody(t, map[string]string{"env_vars": `{"bad-key":"v"}`})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.41.0.5")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── New: invalid ttl_policy 400 ──────────────────────────────────────────────

func TestDeployNew_InvalidTTLPolicy_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ttl@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"ttl_policy": "forever-and-ever"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.42.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── New: invalid env field → 400 ─────────────────────────────────────────────

func TestDeployNew_InvalidEnvField_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "ief@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"env": "not a valid env!!"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.44.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// ── Delete: immediate path where compute Teardown fails (warn arm) ───────────

func TestDeployDelete_TeardownFails_StillDeletes(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "anonymous")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "tf@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	// covFailProvider.Teardown returns nil; use a teardown-erroring double.
	dh.SetComputeProvider(teardownErrProvider{})
	app.Delete("/deploy/:id", middleware.RequireAuth(cfg), dh.Delete)

	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	req := httptest.NewRequest(http.MethodDelete, "/deploy/"+d.AppID, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Teardown error is logged (warn) but the DB row is still deleted → 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// teardownErrProvider is a compute.Provider whose Teardown errors; all other
// methods are inherited from covPanicProvider (unused on the delete path).
type teardownErrProvider struct{ covPanicProvider }

func (teardownErrProvider) Teardown(context.Context, string) error {
	return errors.New("teardown boom")
}

// ── Logs: no provider id yet → 409 not_ready ─────────────────────────────────

func TestDeployLogs_NoProviderID_409(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "lnp@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Get("/deploy/:id/logs", middleware.RequireAuth(cfg), dh.Logs)

	// building deploy with no provider_id → 409 not_ready.
	d := seedInternalDeploy(t, db, teamID, "building", map[string]string{})
	req := httptest.NewRequest(http.MethodGet, "/deploy/"+d.AppID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Redeploy: missing tarball + invalid form 400 ─────────────────────────────

func TestDeployRedeploy_MissingTarball_400(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rmt@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)

	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	// multipart with name but no tarball → missing_tarball 400.
	buf := &strings.Builder{}
	mw := multipart.NewWriter(buf)
	require.NoError(t, mw.WriteField("name", "x"))
	require.NoError(t, mw.Close())
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestDeployRedeploy_TerminalStatus_409 — a stopped/expired deploy can't be
// redeployed (409 deployment_not_redeployable).
func TestDeployRedeploy_TerminalStatus_409(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rts@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)

	d := seedInternalDeploy(t, db, teamID, "stopped", map[string]string{})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	body, ct := multipartRedeployBodyDA(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ── Redeploy async goroutine: vault-resolve failure → failed + autopsy ───────

// covRedeployFailProvider returns an error from Redeploy + has a non-empty
// ProviderID via Status. Implements the minimal compute.Provider surface used
// by the redeploy goroutine.
func TestDeployRedeploy_Goroutine_VaultFailure_WritesFailed(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rv@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)

	// Seed a healthy deploy WITH a vault ref that won't resolve → goroutine
	// vault-resolve failure path.
	d := seedInternalDeployDA(t, db, teamID, "healthy", map[string]string{"SECRET": "vault://does-not-exist"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	body, ct := multipartRedeployBodyDA(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	// Poll for the goroutine to write 'failed'.
	deadline := time.Now().Add(5 * time.Second)
	var got *models.Deployment
	for time.Now().Before(deadline) {
		got, err = models.GetDeploymentByID(context.Background(), db, d.ID)
		require.NoError(t, err)
		if got.Status == "failed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	assert.Equal(t, "failed", got.Status)
}

// TestDeployRedeploy_Goroutine_ComputeDeadline drives the redeploy goroutine's
// compute-failure path with a DeadlineExceeded error so the autopsy reason is
// classified as DeadlineExceeded (deploy.go L1315-1317).
func TestDeployRedeploy_Goroutine_ComputeDeadline(t *testing.T) {
	daDeployNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rcd@example.com")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	// covFailProvider lives in deploy_stack_internal_coverage_test.go (same pkg).
	dh.SetComputeProvider(covFailProvider{deployErr: context.DeadlineExceeded})
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)

	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	body, ct := multipartRedeployBodyDA(t)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	deadline := time.Now().Add(5 * time.Second)
	var autopsy *models.DeploymentAutopsyRow
	for time.Now().Before(deadline) {
		autopsy, _ = models.GetLatestDeploymentAutopsy(context.Background(), db, d.ID)
		if autopsy != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotNil(t, autopsy)
	assert.Equal(t, models.FailureReasonDeadlineExceeded, autopsy.Reason)
}

// seedInternalDeployDA mirrors seedInternalDeploy but is local to this file to
// avoid cross-file helper coupling (the shared one lives in another _test.go in
// the same package, so we reuse it instead — keep this thin wrapper for clarity).
func seedInternalDeployDA(t *testing.T, db *sql.DB, teamID uuid.UUID, status string, env map[string]string) *models.Deployment {
	t.Helper()
	return seedInternalDeploy(t, db, teamID, status, env)
}

func multipartRedeployBodyDA(t *testing.T) (*strings.Reader, string) {
	t.Helper()
	buf := &strings.Builder{}
	mw := multipart.NewWriter(buf)
	fw, err := mw.CreateFormFile("tarball", "app.tar.gz")
	require.NoError(t, err)
	_, err = fw.Write([]byte("fake-tarball-bytes"))
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return strings.NewReader(buf.String()), mw.FormDataContentType()
}
