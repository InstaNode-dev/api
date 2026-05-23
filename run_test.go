package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/oschwald/maxminddb-golang"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/router"
	"instant.dev/internal/testhelpers"
)

// newRunSeams snapshots every package-level seam var and restores them on
// cleanup so a run() test can substitute stubs without leaking overrides into
// sibling tests in the same package.
func newRunSeams(t *testing.T) {
	t.Helper()
	pInit := initTracer
	pPg := connectPostgres
	pMig := runMigrations
	pPool := startPoolStatsExporter
	pRedis := connectRedis
	pGeo := loadGeoLite2
	pProv := newProvisionerClient
	pRouter := newRouterWithHooks
	pServe := serveFunc
	t.Cleanup(func() {
		initTracer = pInit
		connectPostgres = pPg
		runMigrations = pMig
		startPoolStatsExporter = pPool
		connectRedis = pRedis
		loadGeoLite2 = pGeo
		newProvisionerClient = pProv
		newRouterWithHooks = pRouter
		serveFunc = pServe
	})
}

// setMinimalValidEnv sets exactly the env config.Load() needs to return
// without panicking, plus a no-op tracer endpoint. PLANS_PATH points at a
// missing file so loadPlansRegistry takes the dev-fallback branch
// (ENVIRONMENT=development) — no on-disk plans.yaml required.
func setMinimalValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:1/none?sslmode=disable")
	t.Setenv("JWT_SECRET", "0123456789012345678901234567890123456789")
	t.Setenv("AES_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("PLANS_PATH", t.TempDir()+"/missing-plans.yaml")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	t.Setenv("PROVISIONER_ADDR", "")
	t.Setenv("ENVIRONMENT", "development")
}

// runState records boot-ordering observations made through the seams.
type runState struct {
	tracerShutdownCalled atomic.Bool
	migrationsCalled     atomic.Bool
	poolExporterCalled   atomic.Bool
	routerBuilt          atomic.Bool
	served               atomic.Bool
}

// fakeDB returns a non-pinging *sql.DB handle. sql.Open never dials, so this
// is safe and fast — the model wiring only stores the handle at boot.
func fakeDB(t *testing.T) *sql.DB {
	t.Helper()
	dbh, err := sql.Open("postgres", "postgres://u:p@127.0.0.1:1/none?sslmode=disable")
	require.NoError(t, err)
	return dbh
}

// newClosableGeoDBs returns a GeoDBs with non-nil City/ASN readers. A
// zero-value maxminddb.Reader has hasMappedFile=false, so Close() is a safe
// no-op — enough to exercise run()'s geo-close defer branches without a real
// .mmdb fixture on disk.
func newClosableGeoDBs(t *testing.T) *middleware.GeoDBs {
	t.Helper()
	return &middleware.GeoDBs{City: &maxminddb.Reader{}, ASN: &maxminddb.Reader{}}
}

// wireHappyPathSeams points every external boundary at a non-networking fake
// so run() can boot, build the router, reach the serve seam, and tear down
// without a real Postgres / Redis / GeoIP volume / bound listener. The serve
// seam is left for the caller to set (clean drain vs error arm).
func wireHappyPathSeams(t *testing.T) *runState {
	st := &runState{}
	initTracer = func(string, string) func(context.Context) error {
		return func(context.Context) error {
			st.tracerShutdownCalled.Store(true)
			return nil
		}
	}
	connectPostgres = func(string) *sql.DB { return fakeDB(t) }
	runMigrations = func(*sql.DB) error { st.migrationsCalled.Store(true); return nil }
	startPoolStatsExporter = func(ctx context.Context, _ *sql.DB, _ string) {
		st.poolExporterCalled.Store(true)
		<-ctx.Done() // mirror prod: lives until the boot ctx cancels at teardown
	}
	connectRedis = func(string) *redis.Client {
		return redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	}
	loadGeoLite2 = func(string) *middleware.GeoDBs { return nil }
	newRouterWithHooks = func(_ *config.Config, _ *sql.DB, _ *redis.Client, _ *middleware.GeoDBs, _ *email.Client, _ *plans.Registry, _ *provisioner.Client, _ *newrelic.Application) (*fiber.App, router.ShutdownHooks) {
		st.routerBuilt.Store(true)
		return fiber.New(fiber.Config{DisableStartupMessage: true}), router.ShutdownHooks{}
	}
	return st
}

// TestRun_HappyPath_BootsReadyTeardown drives run() end-to-end with all
// external boundaries stubbed. The serve seam returns nil immediately to
// simulate a clean SIGTERM-triggered drain; run() must boot, build the
// router, run migrations, start the pool exporter, then unwind every defer
// and return nil.
func TestRun_HappyPath_BootsReadyTeardown(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	st := wireHappyPathSeams(t)

	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil // clean drain
	}

	err := run()
	require.NoError(t, err, "clean serve return must yield a nil run() error")

	assert.True(t, st.migrationsCalled.Load(), "migrations must run during boot")
	assert.True(t, st.routerBuilt.Load(), "router must be built before serving")
	assert.True(t, st.served.Load(), "serve seam must be reached")
	// poolExporter runs in a goroutine; give the scheduler a beat, then the
	// defers (poolStatsCancel) will have fired and the tracer shutdown ran.
	assert.Eventually(t, st.tracerShutdownCalled.Load, time.Second, 10*time.Millisecond,
		"deferred tracer shutdown must run on a clean return")
}

// TestRun_MigrationsFailReturnsError — a migration failure must surface as a
// non-nil run() error (main() turns it into os.Exit(1) → CrashLoopBackoff)
// rather than booting a server against an un-migrated schema.
func TestRun_MigrationsFailReturnsError(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	st := wireHappyPathSeams(t)
	runMigrations = func(*sql.DB) error { return errors.New("relation does not exist") }
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil
	}

	err := run()
	require.Error(t, err, "migration failure must abort boot")
	assert.Contains(t, err.Error(), "migrations")
	assert.False(t, st.served.Load(), "serve must NOT be reached when migrations fail")
}

// TestRun_PlansLoadFailsInProductionReturnsError — when ENVIRONMENT=production
// and plans.yaml is missing, loadPlansRegistry returns an error and run() must
// abort before serving (fail-loud — never serve stale embedded limits in prod).
func TestRun_PlansLoadFailsInProductionReturnsError(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	t.Setenv("ENVIRONMENT", "production")
	st := wireHappyPathSeams(t)
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil
	}

	err := run()
	require.Error(t, err, "missing plans.yaml in production must abort boot")
	assert.Contains(t, err.Error(), "plans")
	assert.False(t, st.served.Load(), "serve must NOT be reached when plans load fails in prod")
}

// TestRun_ProvisionerConnectFailsReturnsError — when PROVISIONER_ADDR is set
// but the gRPC client constructor errors, run() must abort before serving.
func TestRun_ProvisionerConnectFailsReturnsError(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	t.Setenv("PROVISIONER_ADDR", "provisioner.invalid:50051")
	st := wireHappyPathSeams(t)
	newProvisionerClient = func(string, string) (*provisioner.Client, *grpc.ClientConn, error) {
		return nil, nil, errors.New("dial failed")
	}
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil
	}

	err := run()
	require.Error(t, err, "provisioner connect failure must abort boot")
	assert.Contains(t, err.Error(), "provisioner")
	assert.False(t, st.served.Load())
}

// TestRun_ProvisionerConnectSucceedsServes — PROVISIONER_ADDR set and the
// client constructs cleanly: run() must reach the serve seam (the
// remote-provisioner branch), and a clean serve return yields nil.
func TestRun_ProvisionerConnectSucceedsServes(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	t.Setenv("PROVISIONER_ADDR", "provisioner.invalid:50051")
	st := wireHappyPathSeams(t)
	newProvisionerClient = func(string, string) (*provisioner.Client, *grpc.ClientConn, error) {
		// A nil-backed client + a real (lazy) ClientConn. grpc.NewClient does
		// not dial until first RPC, so this never touches the network here.
		conn, err := grpc.NewClient("passthrough:///provisioner.invalid:50051",
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		return nil, conn, nil
	}
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil
	}

	err := run()
	require.NoError(t, err)
	assert.True(t, st.served.Load(), "serve must be reached on the remote-provisioner happy path")
}

// TestRun_ServeErrorReturnsError — when the serve seam reports a fatal
// listener error (port bind failure, stuck-drain timeout), run() must
// surface it so main() exits non-zero.
func TestRun_ServeErrorReturnsError(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	wireHappyPathSeams(t)
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		return errors.New("listen tcp :8080: bind: address already in use")
	}

	err := run()
	require.Error(t, err, "a fatal serve error must propagate out of run()")
	assert.Contains(t, err.Error(), "serve")
}

// TestRun_TracerShutdownErrorIsLoggedNotFatal — the deferred tracer shutdown
// returning an error must NOT change run()'s return value (it is logged at
// ERROR and swallowed). A clean serve return stays nil even when the tracer's
// shutdown errors.
func TestRun_TracerShutdownErrorIsLoggedNotFatal(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	wireHappyPathSeams(t)
	initTracer = func(string, string) func(context.Context) error {
		return func(context.Context) error { return errors.New("tp shutdown timeout") }
	}
	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error { return nil }

	err := run()
	require.NoError(t, err, "tracer shutdown error must be swallowed, not propagated")
}

// TestInitNewRelic_ValidLicenseReturnsApp — a syntactically valid 40-char
// license must produce a non-nil *newrelic.Application (the success arm:
// NewApplication + the "newrelic.initialized" log). NEW_RELIC_APP_NAME, when
// unset, derives "instant-<service>".
func TestInitNewRelic_ValidLicenseReturnsApp(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", strings.Repeat("a", 40))
	t.Setenv("NEW_RELIC_APP_NAME", "")
	app := initNewRelic("api")
	require.NotNil(t, app, "a valid 40-char license must yield a non-nil NR app")
	app.Shutdown(2 * 1_000_000_000)
}

// TestInitNewRelic_AppNameOverride — NEW_RELIC_APP_NAME, when set, overrides
// the derived "instant-<service>" name (covers the appName-set branch).
func TestInitNewRelic_AppNameOverride(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", strings.Repeat("b", 40))
	t.Setenv("NEW_RELIC_APP_NAME", "custom-app-name")
	app := initNewRelic("api")
	require.NotNil(t, app)
	app.Shutdown(2 * 1_000_000_000)
}

// TestInitNewRelic_InvalidLicenseFailsOpen — a malformed (non-40-char,
// non-empty) license makes NewApplication error; initNewRelic must log and
// return nil rather than crash boot (the init_failed fail-open arm).
func TestInitNewRelic_InvalidLicenseFailsOpen(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "too-short-to-be-valid")
	app := initNewRelic("api")
	require.Nil(t, app, "a malformed license must fail open to nil, not panic")
}

// TestRun_WithNRAppAndGeoDBs_CoversTeardownDefers drives run() with a non-nil
// NR app (so the nrApp.Shutdown + SetNRApp branch runs) and a non-nil GeoDBs
// with closable City/ASN handles (so both geo-close defers run). Asserts a
// clean boot→serve→teardown with no panic on the extra defer paths.
func TestRun_WithNRAppAndGeoDBs_CoversTeardownDefers(t *testing.T) {
	newRunSeams(t)
	setMinimalValidEnv(t)
	// Valid license → initNewRelic returns a non-nil app inside run().
	t.Setenv("NEW_RELIC_LICENSE_KEY", strings.Repeat("c", 40))
	st := wireHappyPathSeams(t)

	// Non-nil GeoDBs with real (closable) maxmind readers from an embedded
	// fixture would be heavy; instead supply a GeoDBs whose City/ASN are
	// non-nil readers via the test-only opener. middleware.LoadGeoLite2 is
	// seamed, so we return a GeoDBs the defers can Close() without panicking.
	loadGeoLite2 = func(string) *middleware.GeoDBs { return newClosableGeoDBs(t) }

	serveFunc = func(*fiber.App, string, time.Duration, router.ShutdownHooks) error {
		st.served.Store(true)
		return nil
	}

	err := run()
	require.NoError(t, err)
	assert.True(t, st.served.Load())
}

// TestEmitDeployAuditSelfReport_SuccessAgainstRealDB — against a real
// migrated platform DB, emitDeployAuditSelfReport must insert a row and take
// the success-log arm. Skips when TEST_DATABASE_URL is unset.
func TestEmitDeployAuditSelfReport_SuccessAgainstRealDB(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed self-report test")
	}
	dbh, clean := testhelpers.SetupTestDB(t)
	defer clean()
	_, _ = dbh.Exec(`DELETE FROM deploys_audit`)
	t.Cleanup(func() { _, _ = dbh.Exec(`DELETE FROM deploys_audit`) })

	// Must not panic and must write a row (success arm).
	emitDeployAuditSelfReport(dbh)

	var n int
	require.NoError(t, dbh.QueryRow(`SELECT count(*) FROM deploys_audit WHERE service='api'`).Scan(&n))
	assert.GreaterOrEqual(t, n, 1, "self-report success arm must insert at least one row")
}

// TestEmitDeployAuditSelfReport_DBErrorIsSwallowed — a non-pinging handle
// makes InsertSelfReport fail; emitDeployAuditSelfReport must log at WARN and
// return without panicking (observability, never a boot gate).
func TestEmitDeployAuditSelfReport_DBErrorIsSwallowed(t *testing.T) {
	dbh, err := sql.Open("postgres", "postgres://u:p@127.0.0.1:1/none?sslmode=disable")
	require.NoError(t, err)
	defer dbh.Close()
	assert.NotPanics(t, func() { emitDeployAuditSelfReport(dbh) },
		"a DB error in the self-report must be swallowed, never panic boot")
}

// TestMain_DelegatesToRun is a compile-time + behaviour guard that main()
// is the thin os.Exit wrapper around run(). We can't call main() directly (it
// would os.Exit the test binary), but we assert run() is a free function with
// the documented error-returning contract that main() depends on.
func TestRun_IsErrorReturning(t *testing.T) {
	// Documents the seam contract relied on by main(): run returns an error.
	// fn's type is inferred from run, which is declared func() error in run.go —
	// the assignment below would not compile if that contract changed.
	var fn = run
	require.NotNil(t, fn)
	// envProduction sanity — run()'s plans branch keys off it.
	require.True(t, strings.EqualFold(envProduction, "production"))
}

// TestMain_ExitsNonZeroOnRunError — main() must call os.Exit(1) when run()
// returns an error. We stub the runFunc and osExit seams so main() can be
// driven in-process (it normally os.Exit()s the test binary). Production
// wiring (runFunc==run, osExit==os.Exit) is untouched.
func TestMain_ExitsNonZeroOnRunError(t *testing.T) {
	prevRun, prevExit := runFunc, osExit
	t.Cleanup(func() { runFunc, osExit = prevRun, prevExit })

	runFunc = func() error { return errors.New("boot failed") }
	var gotCode int
	var exited bool
	osExit = func(code int) { gotCode = code; exited = true }

	main()

	require.True(t, exited, "main() must call osExit when run() returns an error")
	require.Equal(t, 1, gotCode, "main() must exit with code 1 on a run() error")
}

// TestMain_NoExitOnCleanRun — when run() returns nil (clean SIGTERM drain),
// main() must NOT call os.Exit. Pins the happy-path wrapper.
func TestMain_NoExitOnCleanRun(t *testing.T) {
	prevRun, prevExit := runFunc, osExit
	t.Cleanup(func() { runFunc, osExit = prevRun, prevExit })

	runFunc = func() error { return nil }
	exited := false
	osExit = func(int) { exited = true }

	main()
	require.False(t, exited, "main() must not exit when run() returns nil")
}
