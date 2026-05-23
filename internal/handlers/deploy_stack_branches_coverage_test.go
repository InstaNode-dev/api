package handlers_test

// deploy_stack_branches_coverage_test.go — HTTP error-branch + goroutine
// coverage for the remaining sub-95% paths in deploy.go and stack.go.
//
// Scope: deploy.go + stack.go ONLY. All tests skip cleanly when
// TEST_DATABASE_URL is unset.

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
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/crypto"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute"
	"instant.dev/internal/testhelpers"
)

func branchCovNeedsDB(t *testing.T) {
	t.Helper()
	requireTestDB(t)
}

// ── failing stack provider double ────────────────────────────────────────────

type failStackProvider struct {
	deployErr error
}

func (f failStackProvider) DeployStack(_ context.Context, _ compute.StackDeployOptions, onUpdate func(string, string, string, string), onImageBuilt func(string, string)) error {
	return f.deployErr
}
func (f failStackProvider) TeardownStack(context.Context, string) error { return nil }
func (f failStackProvider) ServiceLogs(context.Context, string, string, bool) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (f failStackProvider) RedeployStack(_ context.Context, _ string, _ []compute.StackServiceDef, onUpdate func(string, string, string, string), onImageBuilt func(string, string)) error {
	return f.deployErr
}

// okStackProvider fires the onUpdate + onImageBuilt callbacks so the
// runStackDeploy / runStackRedeploy success paths exercise the callback bodies
// (including the unknown-service warn branch).
type okStackProvider struct{}

func (okStackProvider) DeployStack(_ context.Context, opts compute.StackDeployOptions, onUpdate func(string, string, string, string), onImageBuilt func(string, string)) error {
	for _, s := range opts.Services {
		onUpdate(s.Name, "healthy", "http://x", "")
		onImageBuilt(s.Name, "registry/img:"+s.Name)
		onImageBuilt(s.Name, "") // empty imageRef -> early-return branch
	}
	onUpdate("phantom-service", "healthy", "", "") // unknown-service warn branch
	onImageBuilt("phantom-service", "x")           // unknown-service warn branch
	return nil
}
func (okStackProvider) TeardownStack(context.Context, string) error { return nil }
func (okStackProvider) ServiceLogs(context.Context, string, string, bool) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (okStackProvider) RedeployStack(_ context.Context, _ string, services []compute.StackServiceDef, onUpdate func(string, string, string, string), onImageBuilt func(string, string)) error {
	for _, s := range services {
		onUpdate(s.Name, "healthy", "http://x", "")
		onImageBuilt(s.Name, "registry/img:"+s.Name)
		onImageBuilt(s.Name, "")
	}
	onUpdate("phantom-service", "healthy", "", "")
	onImageBuilt("phantom-service", "x")
	return nil
}

// covLogsFailProvider: Logs() returns an error so the deploy Logs handler hits
// its logs_failed 503 branch.
type covLogsFailProvider struct {
	covPanicProvider
}

func (covLogsFailProvider) Logs(context.Context, string, bool) (io.ReadCloser, error) {
	return nil, errors.New("log stream open failed")
}

func TestDeployLogs_StreamError_Returns503(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "logsfail@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	dh.SetComputeProvider(covLogsFailProvider{})
	app.Get("/deploy/:id/logs", middleware.RequireAuth(cfg), dh.Logs)

	req := httptest.NewRequest(http.MethodGet, "/deploy/"+d.AppID+"/logs", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ── deploy New — input-validation error branches ─────────────────────────────

func TestDeployNew_ServiceDisabled_Returns503(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "svc@example.com")

	// deploy NOT in the enabled-services list.
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "8080"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.1")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestDeployNew_MissingTarball_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "notar@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Multipart with a name field but NO tarball file.
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	require.NoError(t, w.WriteField("name", "no-tarball"))
	require.NoError(t, w.Close())
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.2")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidForm_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badform@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// Non-multipart Content-Type makes c.MultipartForm() return an error
	// inside the handler (vs the framework rejecting the body up front).
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", bytes.NewReader([]byte("not-multipart")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.3")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidPort_NonNumeric_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badport@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "not-a-number"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.4")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_PortOutOfRange_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "rangeport@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"port": "70000"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.5")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestDeployNew_InvalidEnvKey_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badkey@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{
		"env_vars": `{"bad-key":"v"}`, // lowercase + hyphen
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.6")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_env_key", decodeErrCode(t, resp))
}

func TestDeployNew_InvalidResourceBindingsJSON_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badbind@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{
		"resource_bindings": `not-json`,
	})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.7")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_resource_bindings", decodeErrCode(t, resp))
}

func TestDeployNew_InvalidTTLPolicy_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "badttl@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	body, ct := multipartDeployBody(t, map[string]string{"ttl_policy": "forever-and-ever"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.8")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_ttl_policy", decodeErrCode(t, resp))
}

func TestDeployNew_PermanentTTLPolicy_Accepts(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID, "permttl@example.com")
	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "deploy")
	defer cleanApp()

	// ttl_policy=permanent exercises the made_permanent emit branch.
	body, ct := multipartDeployBody(t, map[string]string{"ttl_policy": "permanent"})
	req := httptest.NewRequest(http.MethodPost, "/deploy/new", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-Forwarded-For", "10.40.0.9")
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// ── deploy Redeploy — extra error branches ───────────────────────────────────

// TestRedeploy_GoroutineComputeFailure drives the async redeploy failure path
// (compute.Redeploy errors -> failed status + autopsy) by calling the handler
// with a failing compute provider injected. We poll the DB for the terminal
// 'failed' status the goroutine writes.
func TestRedeploy_GoroutineComputeFailure(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := handlers.NewDeployHandler(db, nil, covCfg(), plans.Default())
	h.SetComputeProvider(covFailProvider{deployErr: errors.New("rollout boom")})

	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))
	d.ProviderID = "noop-prov"

	// runDeploy uses the same compute provider; the redeploy goroutine path is
	// structurally identical (compute err -> failed + autopsy). Exercise via
	// runDeploy which our export wrapper invokes synchronously, then assert.
	handlers.RunDeployForTest(h, d, []byte("tarball"))
	got, err := models.GetDeploymentByID(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
}

// ── stack runStackDeploy / runStackRedeploy goroutine internals ──────────────

func TestRunStackDeploy_Success_AndCallbacks(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := newStackHandlerForCov(t, db)
	h.SetStackProvider(okStackProvider{})

	stack, rows := seedStackWithService(t, db, &teamID, "building", "web")
	opts := compute.StackDeployOptions{
		StackID:  stack.Slug,
		Services: []compute.StackServiceDef{{Name: "web", Port: 8080, Expose: true}},
	}
	handlers.RunStackDeployForTest(h, context.Background(), stack, rows, opts)

	got, err := models.GetStackBySlug(context.Background(), db, stack.Slug)
	require.NoError(t, err)
	assert.Equal(t, "healthy", got.Status)
}

func TestRunStackDeploy_Failure(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	h := newStackHandlerForCov(t, db)
	h.SetStackProvider(failStackProvider{deployErr: errors.New("deploy boom")})

	stack, rows := seedStackWithService(t, db, &teamID, "building", "web")
	opts := compute.StackDeployOptions{
		StackID:  stack.Slug,
		Services: []compute.StackServiceDef{{Name: "web", Port: 8080}},
	}
	handlers.RunStackDeployForTest(h, context.Background(), stack, rows, opts)

	got, err := models.GetStackBySlug(context.Background(), db, stack.Slug)
	require.NoError(t, err)
	assert.Equal(t, "failed", got.Status)
}

func TestRunStackRedeploy_Success_AndFailure(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))

	// success
	hOK := newStackHandlerForCov(t, db)
	hOK.SetStackProvider(okStackProvider{})
	stackOK, rowsOK := seedStackWithService(t, db, &teamID, "building", "web")
	handlers.RunStackRedeployForTest(hOK, context.Background(), stackOK, rowsOK, stackOK.Namespace,
		[]compute.StackServiceDef{{Name: "web", Port: 8080}})
	gotOK, err := models.GetStackBySlug(context.Background(), db, stackOK.Slug)
	require.NoError(t, err)
	assert.Equal(t, "healthy", gotOK.Status)

	// failure
	hFail := newStackHandlerForCov(t, db)
	hFail.SetStackProvider(failStackProvider{deployErr: errors.New("redeploy boom")})
	stackFail, rowsFail := seedStackWithService(t, db, &teamID, "building", "web")
	handlers.RunStackRedeployForTest(hFail, context.Background(), stackFail, rowsFail, stackFail.Namespace,
		[]compute.StackServiceDef{{Name: "web", Port: 8080}})
	gotFail, err := models.GetStackBySlug(context.Background(), db, stackFail.Slug)
	require.NoError(t, err)
	assert.Equal(t, "failed", gotFail.Status)
}

// ── stack checkStackDeployLimit — direct call with a real Redis ──────────────

func TestCheckStackDeployLimit_RealRedis(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	h := handlers.NewStackHandler(db, rdb, cfg, plans.Default())

	fp := "fp-cov-" + uuid.NewString()[:8]
	// First call: well under the anonymous cap -> not exceeded.
	exceeded, err := handlers.CheckStackDeployLimitForTest(h, context.Background(), fp)
	require.NoError(t, err)
	assert.False(t, exceeded, "first provision must be under the cap")

	// Hammer past the anonymous provision cap so the >limit branch fires.
	limit := plans.Default().ProvisionLimit("anonymous")
	var last bool
	for i := 0; i < limit+3; i++ {
		last, err = handlers.CheckStackDeployLimitForTest(h, context.Background(), fp)
		require.NoError(t, err)
	}
	assert.True(t, last, "after exceeding the cap, checkStackDeployLimit must report exceeded")
}

func TestCheckStackDeployLimit_NilRedis_FailsOpen(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	h := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	exceeded, err := handlers.CheckStackDeployLimitForTest(h, context.Background(), "fp-nil")
	require.NoError(t, err)
	assert.False(t, exceeded, "nil Redis must fail open (allow)")
}

// ── stack Redeploy / UpdateEnv — stack_deleting 409 + missing tarball ────────

func TestStackRedeploy_MissingTarballForService_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "missvc@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "healthy", "web")

	app := newStackTestApp(t, db)

	// Manifest references service "web" but we attach NO tarball file.
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	require.NoError(t, w.WriteField("manifest", "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n"))
	require.NoError(t, w.Close())
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+stack.Slug+"/redeploy", buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "missing_tarball", decodeErrCode(t, resp))
}

func TestStackUpdateEnv_StackDeleting_Returns409(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "deleting@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "deleting", "web")

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+stack.Slug+"/env",
		bytes.NewReader([]byte(`{"env":{"FOO":"bar"}}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "stack_deleting", decodeErrCode(t, resp))
}

func TestStackRedeploy_StackDeleting_Returns409(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "rdeleting@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "deleting", "web")

	app := newStackTestApp(t, db)
	buf := &bytes.Buffer{}
	w := multipart.NewWriter(buf)
	require.NoError(t, w.WriteField("manifest", "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n"))
	require.NoError(t, w.Close())
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+stack.Slug+"/redeploy", buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	assert.Equal(t, "stack_deleting", decodeErrCode(t, resp))
}

func TestStackRedeploy_VaultRefUnresolvable_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "vaultfail@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "healthy", "web")

	app := newStackTestApp(t, db)
	// Manifest env carries an unresolvable vault ref -> ResolveVaultRefs errors
	// -> 400 vault_ref_failed.
	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    env:\n      SECRET: vault://does-not-exist-key\n"
	body, ct := stackMultipart(t, manifest, map[string][]byte{"web": newMinimalTarball(t)})
	req := httptest.NewRequest(http.MethodPost, "/stacks/"+stack.Slug+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "vault_ref_failed", decodeErrCode(t, resp))
}

func TestStackUpdateEnv_EmptyStringDeletes(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "del@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "healthy", "web")
	require.NoError(t, models.UpdateStackEnvVars(context.Background(), db, stack.ID, map[string]string{"KEEP": "1", "DROP": "2"}))

	app := newStackTestApp(t, db)
	req := httptest.NewRequest(http.MethodPatch, "/stacks/"+stack.Slug+"/env",
		bytes.NewReader([]byte(`{"env":{"DROP":"","ADD":"3"}}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got, err := models.GetStackEnvVars(context.Background(), db, stack.ID)
	require.NoError(t, err)
	_, hasDrop := got["DROP"]
	assert.False(t, hasDrop, "empty-string value deletes the key")
	assert.Equal(t, "1", got["KEEP"])
	assert.Equal(t, "3", got["ADD"])
}

// ── deploy Redeploy — HTTP path drives the async goroutine (success+fail) ────

// redeployApp builds a minimal app with the deploy Redeploy route wired to a
// handler whose compute provider is `cp`, so the async redeploy goroutine
// runs against the injected double.
func redeployApp(t *testing.T, db *sql.DB, cp compute.Provider) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if fe, ok := e.(*fiber.Error); ok {
				code = fe.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": e.Error()})
		},
	})
	dh := handlers.NewDeployHandler(db, nil, cfg, plans.Default())
	if cp != nil {
		dh.SetComputeProvider(cp)
	}
	app.Post("/deploy/:id/redeploy", middleware.RequireAuth(cfg), dh.Redeploy)
	return app
}

func TestDeployRedeploy_HTTP_GoroutineSuccess(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdok@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	app := redeployApp(t, db, nil) // noop provider -> goroutine succeeds
	body, ct := multipartTarballBody(t, d.AppID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	// Let the async goroutine flip status to healthy.
	pollDeployStatus(t, db, d.ID, "healthy")
}

func TestDeployRedeploy_HTTP_GoroutineComputeFailure(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "rdfail@example.com")
	d := seedInternalDeploy(t, db, teamID, "healthy", map[string]string{"FOO": "bar"})
	require.NoError(t, models.UpdateDeploymentProviderID(context.Background(), db, d.ID, "noop-prov", "http://x"))

	app := redeployApp(t, db, covFailProvider{deployErr: errors.New("redeploy rollout boom")})
	body, ct := multipartTarballBody(t, d.AppID)
	req := httptest.NewRequest(http.MethodPost, "/deploy/"+d.AppID+"/redeploy", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	// The async redeploy goroutine fails -> status flips to failed + autopsy.
	pollDeployStatus(t, db, d.ID, "failed")
	autopsy, err := models.GetLatestDeploymentAutopsy(context.Background(), db, d.ID)
	require.NoError(t, err)
	assert.NotNil(t, autopsy, "redeploy failure must write an autopsy")
}

// pollDeployStatus waits up to ~3s for the deployment row to reach want.
func pollDeployStatus(t *testing.T, db *sql.DB, id uuid.UUID, want string) {
	t.Helper()
	for i := 0; i < 60; i++ {
		got, err := models.GetDeploymentByID(context.Background(), db, id)
		require.NoError(t, err)
		if got.Status == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("deployment %s never reached status %q", id, want)
}

// ── stack New — tier-cap 402 + needs-token validation ───────────────────────

func TestStackNew_OverTierCap_Returns402(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "hobby") // deployments_apps=1
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "cap@example.com")
	// Seed one active (healthy) stack so the team is already AT its cap of 1.
	_, _ = seedStackWithService(t, db, &teamID, "healthy", "web")

	app := newStackTestApp(t, db)
	resp := postStackNew(t, app, jwt, testStackManifestForCov, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusPaymentRequired, resp.StatusCode)
	assert.Equal(t, "deployment_limit_reached", decodeErrCode(t, resp))
}

func TestStackNew_NeedsInvalidToken_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "needbad@example.com")
	app := newStackTestApp(t, db)

	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    needs:\n      - not-a-uuid\n"
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_token", decodeErrCode(t, resp))
}

func TestStackNew_NeedsResourceNotFound_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "neednf@example.com")
	app := newStackTestApp(t, db)

	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    needs:\n      - " + uuid.NewString() + "\n"
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "resource_not_found", decodeErrCode(t, resp))
}

const testStackManifestForCov = "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n"

// TestStackNew_WithNeeds_ResolvesAndInjectsURL covers the needs:-resolution
// happy path in stack New: a real owned resource with an encrypted
// connection_url is decrypted, rewritten to the in-cluster FQDN, and injected
// as DATABASE_URL. Exercises the largest uncovered block in stack.New.
func TestStackNew_WithNeeds_ResolvesAndInjectsURL(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "needok@example.com")

	// Insert a postgres resource owned by the team, with an AES-encrypted
	// connection_url so the decrypt + rewrite path runs.
	aesKey, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(aesKey, "postgres://u:p@pg.instanode.dev:5432/db")
	require.NoError(t, err)
	token := uuid.New()
	_, err = db.Exec(`
		INSERT INTO resources (team_id, token, resource_type, tier, status, env, connection_url, provider_resource_id)
		VALUES ($1, $2, 'postgres', 'pro', 'active', 'production', $3, 'instant-customer-x')
	`, teamID, token, enc)
	require.NoError(t, err)

	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    needs:\n      - " + token.String() + "\n"
	app := newStackTestApp(t, db)
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestStackNew_NeedsDeletedResource_Returns400 covers the deleted-resource
// branch in the needs resolver.
func TestStackNew_NeedsDeletedResource_Returns400(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamIDStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamIDStr, "needdel@example.com")
	token := uuid.New()
	_, err := db.Exec(`
		INSERT INTO resources (team_id, token, resource_type, tier, status, env)
		VALUES ($1, $2, 'postgres', 'pro', 'deleted', 'production')
	`, teamID, token)
	require.NoError(t, err)

	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    needs:\n      - " + token.String() + "\n"
	app := newStackTestApp(t, db)
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "resource_not_found", decodeErrCode(t, resp))
}

// TestStackNew_NeedsCrossTeamResource_Returns403 covers the cross-team
// ownership rejection in the needs resolver (authenticated arm).
func TestStackNew_NeedsCrossTeamResource_Returns403(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	ownerTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeamStr := testhelpers.MustCreateTeamDB(t, db, "pro")
	otherTeamID := uuid.MustParse(otherTeamStr)
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), ownerTeamStr, "needxt@example.com")

	// Resource belongs to the OTHER team.
	token := uuid.New()
	_, err := db.Exec(`
		INSERT INTO resources (team_id, token, resource_type, tier, status, env)
		VALUES ($1, $2, 'postgres', 'pro', 'active', 'production')
	`, otherTeamID, token)
	require.NoError(t, err)

	manifest := "services:\n  web:\n    build: ./web\n    port: 3000\n    expose: true\n    needs:\n      - " + token.String() + "\n"
	app := newStackTestApp(t, db)
	resp := postStackNew(t, app, jwt, manifest, map[string][]byte{"web": createMinimalTarball(t)})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// failLogsStackProvider: ServiceLogs errors so the stack Logs handler hits its
// logs_failed 503 branch.
type failLogsStackProvider struct{ okStackProvider }

func (failLogsStackProvider) ServiceLogs(context.Context, string, string, bool) (io.ReadCloser, error) {
	return nil, errors.New("service log stream failed")
}

func TestStackLogs_StreamError_Returns503(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "logsfailstk@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "healthy", "web")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetStackProvider(failLogsStackProvider{})
	app.Get("/stacks/:slug/logs/:svc", middleware.OptionalAuth(cfg), sh.Logs)

	req := httptest.NewRequest(http.MethodGet, "/stacks/"+stack.Slug+"/logs/web", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// failTeardownStackProvider: TeardownStack errors so doImmediateStackDelete's
// teardown-failed warn branch executes (delete still proceeds).
type failTeardownStackProvider struct{ okStackProvider }

func (failTeardownStackProvider) TeardownStack(context.Context, string) error {
	return errors.New("teardown boom")
}

func TestStackDelete_TeardownFails_StillDeletes(t *testing.T) {
	branchCovNeedsDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	ensureStackTables(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "free")) // free -> immediate delete
	jwt := testhelpers.MustSignSessionJWT(t, uuid.NewString(), teamID.String(), "tdfail@example.com")
	stack, _ := seedStackWithService(t, db, &teamID, "healthy", "web")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, AESKey: testhelpers.TestAESKeyHex, ComputeProvider: "noop"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	sh := handlers.NewStackHandler(db, nil, cfg, plans.Default())
	sh.SetStackProvider(failTeardownStackProvider{})
	app.Delete("/stacks/:slug", middleware.OptionalAuth(cfg), sh.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/stacks/"+stack.Slug, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Teardown error is swallowed; the row is still deleted -> 200.
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func newStackHandlerForCov(t *testing.T, db *sql.DB) *handlers.StackHandler {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:       testhelpers.TestJWTSecret,
		AESKey:          testhelpers.TestAESKeyHex,
		ComputeProvider: "noop",
	}
	return handlers.NewStackHandler(db, nil, cfg, plans.Default())
}

// seedStackWithService inserts a stack + one named service row and returns the
// loaded *models.Stack plus a serviceRows map keyed by service name (the shape
// runStackDeploy / runStackRedeploy expect).
func seedStackWithService(t *testing.T, db *sql.DB, teamID *uuid.UUID, status, svcName string) (*models.Stack, map[string]*models.StackService) {
	t.Helper()
	slug := "stk-cov-" + uuid.NewString()[:10]
	namespace := "instant-stack-" + slug
	var stackID uuid.UUID
	require.NoError(t, db.QueryRow(`
		INSERT INTO stacks (team_id, slug, namespace, status, tier, env)
		VALUES ($1, $2, $3, $4, 'pro', 'production')
		RETURNING id
	`, teamID, slug, namespace, status).Scan(&stackID))
	_, err := db.Exec(`
		INSERT INTO stack_services (stack_id, name, port, status, expose)
		VALUES ($1, $2, 8080, 'building', true)
	`, stackID, svcName)
	require.NoError(t, err)

	stack, err := models.GetStackBySlug(context.Background(), db, slug)
	require.NoError(t, err)
	svcs, err := models.GetStackServicesByStack(context.Background(), db, stackID)
	require.NoError(t, err)
	rows := make(map[string]*models.StackService, len(svcs))
	for _, s := range svcs {
		rows[s.Name] = s
	}
	return stack, rows
}

func decodeErrCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &out)
	resp.Body = io.NopCloser(bytes.NewReader(b))
	return out.Error
}
