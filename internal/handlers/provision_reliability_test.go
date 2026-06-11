package handlers_test

// provision_reliability_test.go — covers the three reliability fixes shipped in
// fix/api-provision-reliability-pause-retry-rollback:
//
//   FIX 1 — runProviderWithRetry: a transient pause/resume provider failure is
//           retried with bounded backoff (so a single blip doesn't 503 the
//           customer — the live pause-503 dogfood); a permanent failure
//           (malformed/empty SQL identifier, unparseable URL) fails fast.
//   FIX 2 — finalizeProvision is panic-safe: a crash AFTER the backend Provision
//           succeeds but BEFORE the row flips pending→active tears down the
//           backend + marks the row 'failed' (no leaked 'pending' row), then
//           re-raises the panic.
//   FIX 3 — GET /api/v1/deployments/:id surfaces status_reason="sleeping" on a
//           'healthy' row that is scaled_to_zero (replicas=0), so the agent /
//           dashboard doesn't show a sleeping app as up.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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
	"instant.dev/internal/testhelpers"
)

// ─────────────────────────────────────────────────────────────────────────────
// FIX 1 — runProviderWithRetry
// ─────────────────────────────────────────────────────────────────────────────

// TestRunProviderWithRetry_TransientThenSuccess proves the core pause-503 fix:
// a provider op that fails transiently on the first attempt and succeeds on a
// retry returns nil (no 503), and the backoff sleep seam is exercised exactly
// once (one retry gap before the second attempt).
func TestRunProviderWithRetry_TransientThenSuccess(t *testing.T) {
	var sleeps int32
	restore := handlers.SetProviderRetrySleepForTest(func(time.Duration) { atomic.AddInt32(&sleeps, 1) })
	defer restore()

	var calls int32
	op := func(context.Context) error {
		if atomic.AddInt32(&calls, 1) == 1 {
			return errors.New("connection refused") // transient
		}
		return nil
	}

	err := handlers.RunProviderWithRetryForTest(context.Background(), "test.retry", uuid.New(), op)
	require.NoError(t, err, "a transient failure that clears on retry must NOT surface an error")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "op must run twice (1 fail + 1 success)")
	assert.Equal(t, int32(1), atomic.LoadInt32(&sleeps), "exactly one backoff sleep before the retry")
}

// TestRunProviderWithRetry_PermanentFailsFast proves a permanent error
// (errPermanentProviderFailure) is NOT retried — it returns on the first attempt
// with no backoff sleep, so the handler can map it to a distinct 422 instead of
// telling the customer to "retry in a few seconds".
func TestRunProviderWithRetry_PermanentFailsFast(t *testing.T) {
	var sleeps int32
	restore := handlers.SetProviderRetrySleepForTest(func(time.Duration) { atomic.AddInt32(&sleeps, 1) })
	defer restore()

	var calls int32
	permanent := handlers.ValidateSQLIdentForTest("") // empty identifier → permanent
	require.ErrorIs(t, permanent, handlers.ErrPermanentProviderFailureForTest,
		"validateSQLIdent('') must classify as permanent")

	op := func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return permanent
	}

	err := handlers.RunProviderWithRetryForTest(context.Background(), "test.permanent", uuid.New(), op)
	require.ErrorIs(t, err, handlers.ErrPermanentProviderFailureForTest)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "permanent error must fail fast — no retry")
	assert.Equal(t, int32(0), atomic.LoadInt32(&sleeps), "permanent error must not sleep/backoff")
}

// TestRunProviderWithRetry_ExhaustsAndReturnsLastError proves a persistently
// transient failure is retried up to the attempt budget and then returns the
// last error (mapped to 503 by the handler).
func TestRunProviderWithRetry_ExhaustsAndReturnsLastError(t *testing.T) {
	restore := handlers.SetProviderRetrySleepForTest(func(time.Duration) {})
	defer restore()

	var calls int32
	wantErr := errors.New("customer DB unreachable")
	op := func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		return wantErr
	}

	err := handlers.RunProviderWithRetryForTest(context.Background(), "test.exhaust", uuid.New(), op)
	require.ErrorIs(t, err, wantErr, "after exhausting retries the last error is returned")
	assert.Equal(t, int32(handlers.ProviderRetryAttemptsForTest), atomic.LoadInt32(&calls),
		"op must run exactly the full attempt budget")
}

// TestRunProviderWithRetry_CancelledContextStops proves a cancelled request
// context short-circuits the loop without starting a fresh attempt. The first
// attempt runs (ctx not yet cancelled at entry), fails transiently, and the
// second iteration's ctx.Err() check returns the last error instead of retrying.
func TestRunProviderWithRetry_CancelledContextStops(t *testing.T) {
	var slept int32
	restore := handlers.SetProviderRetrySleepForTest(func(time.Duration) { atomic.AddInt32(&slept, 1) })
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	wantErr := errors.New("transient blip")
	var calls int32
	op := func(context.Context) error {
		atomic.AddInt32(&calls, 1)
		cancel() // cancel mid-flight so the next iteration's ctx.Err() guard fires
		return wantErr
	}

	err := handlers.RunProviderWithRetryForTest(ctx, "test.cancel", uuid.New(), op)
	require.ErrorIs(t, err, wantErr, "a cancelled context returns the last transient error")
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "no fresh attempt after cancellation")
}

// TestRunProviderWithRetry_CancelledBeforeFirstAttempt proves that when the ctx
// is ALREADY cancelled before any op runs, the loop returns the ctx error and
// never invokes the op.
func TestRunProviderWithRetry_CancelledBeforeFirstAttempt(t *testing.T) {
	restore := handlers.SetProviderRetrySleepForTest(func(time.Duration) {})
	defer restore()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls int32
	op := func(context.Context) error { atomic.AddInt32(&calls, 1); return nil }

	err := handlers.RunProviderWithRetryForTest(ctx, "test.precancel", uuid.New(), op)
	require.ErrorIs(t, err, context.Canceled, "pre-cancelled ctx returns the ctx error")
	assert.Equal(t, int32(0), atomic.LoadInt32(&calls), "op must never run on a pre-cancelled ctx")
}

// TestValidateSQLIdent_PermanentClassification proves both invalid-identifier
// arms (empty + unsafe char) are classified permanent so the retry never wastes
// the backoff budget on them.
func TestValidateSQLIdent_PermanentClassification(t *testing.T) {
	require.ErrorIs(t, handlers.ValidateSQLIdentForTest(""), handlers.ErrPermanentProviderFailureForTest,
		"empty identifier is a permanent failure")
	require.ErrorIs(t, handlers.ValidateSQLIdentForTest("bad name!"), handlers.ErrPermanentProviderFailureForTest,
		"unsafe-character identifier is a permanent failure")
	require.NoError(t, handlers.ValidateSQLIdentForTest("db_abc-123"), "a valid identifier passes")
}

// ── FIX 1 — handler-level permanent-failure 422 (invalid_resource_state) ──────

// permanentFailureApp mounts the resource routes with a CustomerDatabaseURL set
// (so pauseProvider does NOT short-circuit to the no-op test path) and a
// MongoAdminURI for the mongo arm. The connection_url stored on the resource has
// NO userinfo, so extractURLUsername returns "" → validateSQLIdent("") →
// errPermanentProviderFailure, which must surface as 422 — NOT a 503 telling the
// customer to retry a deterministically-failing call.
func permanentFailureApp(t *testing.T) (*fiber.App, *sql.DB, string) {
	t.Helper()
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{
		Environment:         "test",
		AESKey:              testhelpers.TestAESKeyHex,
		CustomerDatabaseURL: "postgres://nobody@127.0.0.1:1/x?sslmode=disable&connect_timeout=1",
	}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")

	app := fiber.New(fiber.Config{ErrorHandler: reliabilityErrorHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, team)
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	app.Post("/r/:id/pause", h.Pause)
	app.Post("/r/:id/resume", h.Resume)
	return app, db, team
}

// reliabilityErrorHandler swallows the ErrResponseWritten sentinel (respondError
// has already written the body) so the test app doesn't overwrite the handler's
// 422/503 with a fiber default 500.
func reliabilityErrorHandler(c *fiber.Ctx, err error) error {
	if errors.Is(err, handlers.ErrResponseWritten) {
		return nil
	}
	return fiber.DefaultErrorHandler(c, err)
}

// encryptNoUserinfoURL produces a stored connection_url whose decrypted form has
// no userinfo, so the username extraction yields "" (the permanent class).
func encryptNoUserinfoURL(t *testing.T, db *sql.DB, team, status string) string {
	t.Helper()
	key, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	enc, err := crypto.Encrypt(key, "postgres://host:5432/db_x") // NO user:pass
	require.NoError(t, err)
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, 'postgres', 'pro', $2, $3) RETURNING token::text`,
		team, status, enc,
	).Scan(&token))
	return token
}

func doPost(t *testing.T, app *fiber.App, path string) int {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodPost, path, nil), 10000)
	require.NoError(t, err)
	resp.Body.Close()
	return resp.StatusCode
}

// TestPause_PermanentProviderFailure_422 proves a deterministic provider failure
// (malformed stored credentials → empty SQL identifier) returns 422
// invalid_resource_state, NOT the transient 503 "retry in a few seconds".
func TestPause_PermanentProviderFailure_422(t *testing.T) {
	app, db, team := permanentFailureApp(t)
	token := encryptNoUserinfoURL(t, db, team, "active")
	assert.Equal(t, fiber.StatusUnprocessableEntity, doPost(t, app, "/r/"+token+"/pause"),
		"a permanent provider failure must be 422, not a retry-me 503")
	// The DB row must stay 'active' — a failed pause never flips state.
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE token=$1::uuid`, token).Scan(&status))
	assert.Equal(t, "active", status, "row must stay active when the provider pause failed")
}

// TestPause_RedisUnparseableURL_PermanentFailure_422 proves the redis ParseURL
// permanent-classification arm: a stored URL that url.Parse accepts (yielding a
// username) but redis.ParseURL rejects (wrong scheme) is a deterministic failure
// → 422, not a transient 503.
func TestPause_RedisUnparseableURL_PermanentFailure_422(t *testing.T) {
	db, dbClean := testhelpers.SetupTestDB(t)
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(func() { dbClean(); rClean() })
	cfg := &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex}
	h := handlers.NewResourceHandler(db, rdb, cfg, plans.Default(), nil, nil)
	team := testhelpers.MustCreateTeamDB(t, db, "pro")

	app := fiber.New(fiber.Config{ErrorHandler: reliabilityErrorHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, team)
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	app.Post("/r/:id/pause", h.Pause)

	key, err := crypto.ParseAESKey(testhelpers.TestAESKeyHex)
	require.NoError(t, err)
	// http scheme: url.Parse extracts user "usr_x", redis.ParseURL rejects it.
	enc, err := crypto.Encrypt(key, "http://usr_x:pw@host:6379/0")
	require.NoError(t, err)
	var token string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`INSERT INTO resources (team_id, resource_type, tier, status, connection_url)
		 VALUES ($1::uuid, 'redis', 'pro', 'active', $2) RETURNING token::text`,
		team, enc,
	).Scan(&token))

	assert.Equal(t, fiber.StatusUnprocessableEntity, doPost(t, app, "/r/"+token+"/pause"),
		"an unparseable redis URL is a permanent failure → 422")
}

// TestResume_PermanentProviderFailure_422 mirrors the pause case for resume —
// and proves resume stays NEVER tier-gated even on the permanent path (the team
// is Pro here, but the 422 is the credential issue, not a tier wall).
func TestResume_PermanentProviderFailure_422(t *testing.T) {
	app, db, team := permanentFailureApp(t)
	token := encryptNoUserinfoURL(t, db, team, "paused")
	assert.Equal(t, fiber.StatusUnprocessableEntity, doPost(t, app, "/r/"+token+"/resume"),
		"a permanent provider failure on resume must be 422, not a retry-me 503")
	var status string
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT status FROM resources WHERE token=$1::uuid`, token).Scan(&status))
	assert.Equal(t, "paused", status, "row must stay paused when the provider resume failed")
}

// ── FIX 1 — DB-flip-failure rollback path (runProviderWithRetry rollback) ─────

// reliabilityResourceRow builds a sqlmock row matching models.resourceColumns
// (26 cols) for a pro-tier resource owned by teamID with the given status and a
// NULL connection_url (so the no-op provider arm runs with no CustomerDatabaseURL).
func reliabilityResourceRow(token, teamID uuid.UUID, status string) *sqlmock.Rows {
	cols := []string{
		"id", "team_id", "token", "resource_type", "name", "connection_url", "key_prefix",
		"tier", "env", "fingerprint", "cloud_vendor", "country_code", "status",
		"migration_status", "expires_at", "storage_bytes", "provider_resource_id", "created_request_id",
		"parent_resource_id", "paused_at",
		"last_seen_at", "degraded", "degraded_reason", "last_reconciled_at",
		"auth_mode", "created_at",
	}
	return sqlmock.NewRows(cols).AddRow(
		uuid.New(), teamID, token, "postgres", nil, nil, nil,
		"pro", "production", nil, nil, nil, status,
		nil, nil, int64(0), nil, nil,
		nil, nil,
		nil, false, nil, nil,
		"isolated", time.Now(),
	)
}

// reliabilityTeamRow builds the GetTeamByID row (pro tier so the Pause tier gate
// passes; resume is never tier-gated).
func reliabilityTeamRow(teamID uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "name", "plan_tier", "stripe_customer_id", "created_at", "ttl_policy"}).
		AddRow(teamID, "t", "pro", nil, time.Now(), "auto_24h")
}

func reliabilityMockApp(t *testing.T, db *sql.DB, teamID uuid.UUID) *fiber.App {
	t.Helper()
	rdb, rClean := testhelpers.SetupTestRedis(t)
	t.Cleanup(rClean)
	h := handlers.NewResourceHandler(db, rdb, &config.Config{Environment: "test", AESKey: testhelpers.TestAESKeyHex},
		plans.Default(), nil, nil)
	app := fiber.New(fiber.Config{ErrorHandler: reliabilityErrorHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	app.Post("/r/:id/pause", h.Pause)
	app.Post("/r/:id/resume", h.Resume)
	return app
}

// TestPause_DBFlipFails_RollbackPath drives the Pause db_update_failed rollback
// arm: provider revoke succeeds (no-op), then PauseResource's UPDATE errors with
// a non-race error → the handler runs the runProviderWithRetry rollback and
// returns 503 pause_failed.
func TestPause_DBFlipFails_RollbackPath(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID, token := uuid.New(), uuid.New()
	mock.ExpectQuery(`FROM resources WHERE token`).WithArgs(token).
		WillReturnRows(reliabilityResourceRow(token, teamID, "active"))
	mock.ExpectQuery(`FROM teams WHERE id`).WithArgs(teamID).
		WillReturnRows(reliabilityTeamRow(teamID))
	// PauseResource UPDATE fails with a non-race error → rollback path.
	mock.ExpectExec(`UPDATE\s+resources\s+SET status = 'paused'`).
		WillReturnError(errors.New("pause update boom"))

	app := reliabilityMockApp(t, db, teamID)
	assert.Equal(t, fiber.StatusServiceUnavailable, doPost(t, app, "/r/"+token.String()+"/pause"))
}

// TestResume_DBFlipFails_RollbackPath mirrors the above for resume.
func TestResume_DBFlipFails_RollbackPath(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID, token := uuid.New(), uuid.New()
	mock.ExpectQuery(`FROM resources WHERE token`).WithArgs(token).
		WillReturnRows(reliabilityResourceRow(token, teamID, "paused"))
	// ResumeResource UPDATE fails with a non-race error → rollback path.
	mock.ExpectExec(`UPDATE\s+resources\s+SET status = 'active'`).
		WillReturnError(errors.New("resume update boom"))

	app := reliabilityMockApp(t, db, teamID)
	assert.Equal(t, fiber.StatusServiceUnavailable, doPost(t, app, "/r/"+token.String()+"/resume"))
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 2 — finalizeProvision panic safety
// ─────────────────────────────────────────────────────────────────────────────

// TestFinalizeProvision_PanicMarksFailedAndDeprovisions proves the #285-follow-up
// fix: a panic AFTER the backend Provision succeeded but BEFORE the row flips
// pending→active must (a) run the cleanup closure (best-effort backend teardown),
// (b) mark the row 'failed' (no stranded 'pending' row, quota stays correct), and
// (c) re-raise the panic (the panic is a real bug; we don't swallow it).
func TestFinalizeProvision_PanicMarksFailedAndDeprovisions(t *testing.T) {
	dbConn, clean := testhelpers.SetupTestDB(t)
	defer clean()

	ctx := context.Background()

	res, err := models.CreateResource(ctx, dbConn, models.CreateResourceParams{
		ResourceType: "postgres",
		Name:         "finalize-panic-guard",
		Tier:         "anonymous",
		Env:          "development",
		Fingerprint:  "fp-finalize-panic",
	})
	require.NoError(t, err)
	require.Equal(t, "pending", res.Status, "precondition: row must start 'pending'")

	// Install the crash-injection hook so finalizeProvision panics mid-body.
	restore := handlers.SetFinalizeProvisionPanicHookForTest(func() {
		panic("simulated mid-finalize crash")
	})
	defer restore()

	cfg := &config.Config{AESKey: "0000000000000000000000000000000000000000000000000000000000000000"}

	var cleanupRan atomic.Bool
	cleanup := func() { cleanupRan.Store(true) }

	// The helper must re-raise the panic — capture it so the test can continue
	// and assert the reconciliation side effects.
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = handlers.RunFinalizeProvisionForTest(
			ctx, dbConn, cfg, res,
			"postgres://test/dsn", "", "prid-panic-1",
			"req-panic", "test.finalize_panic", cleanup,
		)
	}()

	require.NotNil(t, recovered, "the panic MUST be re-raised, not swallowed")
	assert.True(t, cleanupRan.Load(), "cleanup (backend teardown) must run on a mid-finalize panic")

	// The row must be terminal 'failed', not stranded 'pending'.
	got, err := models.GetResourceByToken(ctx, dbConn, res.Token)
	require.NoError(t, err)
	assert.Equal(t, models.StatusFailed, got.Status,
		"a mid-finalize panic must leave the row 'failed' — never stranded 'pending'")
}

// TestFinalizeProvision_PanicMarkFailedAlsoFails covers the recover path's inner
// "MarkResourceFailed itself errored" log branch: when the platform DB is
// unreachable during the panic recovery, the helper still re-raises the panic
// (it never swallows it) — it just can't reconcile the row. Uses sqlmock so the
// MarkResourceFailed UPDATE returns an error.
func TestFinalizeProvision_PanicMarkFailedAlsoFails(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectExec(`UPDATE resources SET status = 'failed'`).
		WillReturnError(errors.New("platform db down"))

	res := &models.Resource{ID: uuid.New(), ResourceType: "postgres", Status: "pending"}
	restore := handlers.SetFinalizeProvisionPanicHookForTest(func() { panic("boom during finalize") })
	defer restore()

	var cleanupRan atomic.Bool
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		_ = handlers.RunFinalizeProvisionForTest(
			context.Background(), db,
			&config.Config{AESKey: "0000000000000000000000000000000000000000000000000000000000000000"},
			res, "postgres://test/dsn", "", "prid", "req", "test.panic_markfail",
			func() { cleanupRan.Store(true) },
		)
	}()

	require.NotNil(t, recovered, "panic must still be re-raised even when MarkResourceFailed fails")
	assert.True(t, cleanupRan.Load(), "cleanup still runs even when the row can't be reconciled")
	require.NoError(t, mock.ExpectationsWereMet())
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX 3 — deploy status_reason="sleeping"
// ─────────────────────────────────────────────────────────────────────────────

// TestDeploymentToMap_ScaledToZero_StatusReasonSleeping proves a 'healthy' row
// that is scaled_to_zero surfaces status_reason="sleeping" so the agent/dashboard
// can tell the app is asleep (replicas=0, 404s until woken) even though status
// stays "healthy".
func TestDeploymentToMap_ScaledToZero_StatusReasonSleeping(t *testing.T) {
	d := &models.Deployment{
		ID:           uuid.New(),
		AppID:        "app-sleeping",
		Status:       models.DeployStatusHealthy,
		ScaledToZero: true,
		EnvVars:      map[string]string{},
	}
	m := handlers.DeploymentToMapForTest(d)
	assert.Equal(t, "healthy", m["status"], "status field is unchanged (the deploy did succeed)")
	assert.Equal(t, "sleeping", m["status_reason"],
		"a scaled-to-zero healthy deployment must carry status_reason=sleeping")
}

// TestDeploymentToMap_AwakeHealthy_NoStatusReason proves the field is OMITTED on
// a normal awake healthy deployment (compact shape preserved — no regression for
// existing callers).
func TestDeploymentToMap_AwakeHealthy_NoStatusReason(t *testing.T) {
	d := &models.Deployment{
		ID:           uuid.New(),
		AppID:        "app-awake",
		Status:       models.DeployStatusHealthy,
		ScaledToZero: false,
		EnvVars:      map[string]string{},
	}
	m := handlers.DeploymentToMapForTest(d)
	_, has := m["status_reason"]
	assert.False(t, has, "an awake healthy deployment must NOT carry status_reason")
}

// TestDeploymentToMap_BuildingScaledToZero_NoStatusReason proves status_reason is
// only emitted for the healthy+sleeping case — a non-healthy status (e.g. while a
// row carries scaled_to_zero from a prior cycle but is mid-rebuild) keeps its own
// status semantics and does not get the sleeping label.
func TestDeploymentToMap_BuildingScaledToZero_NoStatusReason(t *testing.T) {
	d := &models.Deployment{
		ID:           uuid.New(),
		AppID:        "app-building",
		Status:       models.DeployStatusBuilding,
		ScaledToZero: true,
		EnvVars:      map[string]string{},
	}
	m := handlers.DeploymentToMapForTest(d)
	_, has := m["status_reason"]
	assert.False(t, has, "status_reason=sleeping is gated on status==healthy")
}
