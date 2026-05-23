// TODO(obs-merge): replace obsstubs imports with common/buildinfo and
// common/logctx once Tracks 1 + 2 of the observability rollout land on
// master. The stubs at internal/obsstubs/{buildinfo,logctx} match the
// exported surface of those packages 1:1; the merge agent should rewrite
// the import paths and delete the obsstubs directory.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/newrelic/go-agent/v3/newrelic"
	"google.golang.org/grpc"
	"instant.dev/common/buildinfo"
	"instant.dev/common/logctx"
	"instant.dev/internal/config"
	"instant.dev/internal/db"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/router"
	"instant.dev/internal/telemetry"
)

// serviceName is the value of the `service` field stamped on every log
// line emitted by this binary. The slog handler, the OTel resource, and
// the NR app name all share this string so trace_id / log line / NR
// transaction all join cleanly in queries.
const serviceName = "api"

// External boundaries are routed through package-level function variables so
// the run() seam can be exercised end-to-end (boot → ready → teardown, plus
// every failure arm) in a unit test without a real Postgres, Redis, GeoIP
// volume, or a bound TCP listener. In production every var holds its real
// implementation, so behaviour is byte-for-byte identical to inlining the
// call — this is a test seam, not a behaviour change. Do NOT change what the
// production defaults point at (notably telemetry.InitTracer — P0-2 OTel
// tracing contract); only override them in tests.
var (
	initTracer            = telemetry.InitTracer
	connectPostgres       = db.ConnectPostgres
	runMigrations         = db.RunMigrations
	startPoolStatsExporter = db.StartPoolStatsExporter
	connectRedis          = db.ConnectRedis
	loadGeoLite2          = middleware.LoadGeoLite2
	newProvisionerClient  = provisioner.NewClient
	newRouterWithHooks    = router.NewWithHooks
	serveFunc             = runServerWithGracefulShutdown

	// runFunc / osExit are seams so main() — the one statement that calls
	// os.Exit and thus can't run in-process under `go test` — is exercised
	// with a stubbed exit. In production runFunc == run and osExit ==
	// os.Exit, so behaviour is identical.
	runFunc = run
	osExit  = os.Exit
)

func main() {
	if err := runFunc(); err != nil {
		slog.Error("server.fatal", "error", err)
		osExit(1)
	}
}

// run is the extracted body of main(). It returns an error instead of
// calling os.Exit so it can be driven from a unit test; main() is the only
// production caller and turns a non-nil error into os.Exit(1). The boot
// ordering, defers, and fail-open contracts are identical to the previous
// inline main() — every external call goes through a package-level seam var
// (defaulting to the real implementation) purely so a test can substitute a
// stub. A nil return is a clean SIGTERM-triggered graceful shutdown.
func run() (runErr error) {
	// Structured JSON logging — wrapped in logctx.Handler so every record
	// is decorated with service, commit_id, trace_id, team_id, tid.
	//
	// AddSource gives file:line of the slog call site (caller field in
	// the design doc). Done before any other slog call in run so even
	// telemetry init failures land enriched.
	base := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	})
	ctxH := logctx.NewHandler(serviceName, base)
	// Default to a non-scrubbing handler. Once cfg.Load() resolves
	// ADMIN_PATH_PREFIX below, we re-set the default with a Scrubber
	// wrapped around the same context handler. Until then, any startup
	// log line predates the admin-routes registration and can't possibly
	// contain the prefix value anyway (the prefix is unread at this point).
	slog.SetDefault(slog.New(ctxH))

	shutdownTracer := initTracer("instant-api", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	defer func() {
		if err := shutdownTracer(context.Background()); err != nil {
			slog.Error("telemetry.shutdown_failed", "error", err)
		}
	}()

	// New Relic Go agent. Fail-open on empty / missing license so local
	// dev and CI runs (which never get a real key) still boot. Matches
	// the contract of telemetry.InitTracer above.
	nrApp := initNewRelic(serviceName)
	if nrApp != nil {
		defer nrApp.Shutdown(10_000_000_000) // 10s, in nanoseconds (NR's API)
		middleware.SetNRApp(nrApp)
	}

	cfg := config.Load() // panics on missing required env vars

	// Re-set the slog default with the admin-prefix scrubber wrapped on the
	// outside of the context handler. The scrubber runs LAST so any field
	// (including ones stamped by middleware downstream) is rewritten before
	// the JSON encoder sees it. NewLogScrubber returns the inner handler
	// unchanged when cfg.AdminPathPrefix is empty — zero overhead when
	// admin routes are disabled.
	slog.SetDefault(slog.New(middleware.NewLogScrubber(ctxH, cfg.AdminPathPrefix)))

	database := connectPostgres(cfg.DatabaseURL)
	defer func() { _ = database.Close() }()

	if err := runMigrations(database); err != nil {
		slog.Error("main.migrations_failed", "error", err)
		return fmt.Errorf("migrations: %w", err)
	}

	// Pool-saturation observability (Wave-3 chaos verify, 2026-05-21).
	// A goroutine ticks every 5s and re-publishes *sql.DB.Stats onto
	// instant_pg_pool_* Prometheus gauges so an operator can SEE the
	// pool fill up before downstream consumers (worker email
	// forwarder) start failing with "remaining connection slots are
	// reserved for non-replication superuser connections". Lives for
	// the process lifetime — the goroutine returns when poolStatsCtx
	// is cancelled at shutdown (see Phase A/B handlers below).
	poolStatsCtx, poolStatsCancel := context.WithCancel(context.Background())
	defer poolStatsCancel()
	go startPoolStatsExporter(poolStatsCtx, database, "platform_db")

	// Deploy-audit self-report. Idempotent on (service, commit_id,
	// image_digest) — every pod startup of the same image is a no-op
	// at the DB level, so a 10-replica autoscale or a routine restart
	// writes at most one row. Failures here are non-fatal: this is
	// observability, not a correctness gate, and a DB hiccup on boot
	// must not stop the server from listening.
	emitDeployAuditSelfReport(database)

	rdb := connectRedis(cfg.RedisURL)
	defer func() { _ = rdb.Close() }()

	geoDbs := loadGeoLite2(cfg.GeoLite2DBPath)
	if geoDbs != nil && geoDbs.City != nil {
		defer func() { _ = geoDbs.City.Close() }()
	}
	if geoDbs != nil && geoDbs.ASN != nil {
		defer func() { _ = geoDbs.ASN.Close() }()
	}

	emailClient := email.New(email.Config{
		Provider:     cfg.EmailProvider,
		BrevoAPIKey:  cfg.BrevoAPIKey,
		ResendAPIKey: cfg.ResendAPIKey,
		FromName:     cfg.EmailFromName,
		FromAddress:  cfg.EmailFromAddress,
	})
	// EMAIL-BUGBASH C3: consult the email_events suppression table before
	// every synchronous api send (magic link, receipt, dunning, invite,
	// deletion confirm) so api-originated mail never reaches a hard-bounced,
	// unsubscribed, or spam-complaining address. Fail-open on a DB error.
	emailClient = emailClient.WithSuppressionChecker(models.NewSuppressionChecker(database))
	// P0-1 (CIRCUIT-RETRY-AUDIT-2026-05-20): wire the email_send_dedup
	// ledger so every keyed Send* call (the *WithKey variants used by
	// payment receipts, dunning, team-invite, deletion-confirm) probes
	// the ledger before sending and records the key after the upstream
	// provider 2xx'd. A network-glitch retry between provider 2xx and
	// our handler reading the response collapses to one delivered email.
	emailClient = emailClient.WithSendLedger(models.NewEmailDedupLedger(database))

	plansPath := os.Getenv("PLANS_PATH")
	if plansPath == "" {
		plansPath = "plans.yaml"
	}
	planRegistry, err := loadPlansRegistry(plansPath, cfg.Environment)
	if err != nil {
		// loadPlansRegistry only returns a non-nil error in production —
		// dev / staging warn-and-fallback to embedded defaults. Falling
		// back in prod would silently serve stale limits/pricing because
		// plans.yaml is the declared single source of truth. Fatal here
		// so a misconfigured prod pod surfaces as CrashLoopBackoff
		// (operator-visible) instead of green /healthz with wrong limits.
		slog.Error("plans.load_failed", "error", err, "path", plansPath, "environment", cfg.Environment)
		return fmt.Errorf("plans load: %w", err)
	}

	var provClient *provisioner.Client
	if cfg.ProvisionerAddr != "" {
		var conn *grpc.ClientConn
		provClient, conn, err = newProvisionerClient(cfg.ProvisionerAddr, cfg.ProvisionerSecret)
		if err != nil {
			slog.Error("main.provisioner_connect_failed", "error", err)
			return fmt.Errorf("provisioner connect: %w", err)
		}
		defer func() { _ = conn.Close() }()
		slog.Info("main.provisioner_connected", "addr", cfg.ProvisionerAddr)
	} else {
		slog.Info("main.provisioner_local", "note", "PROVISIONER_ADDR not set, using local providers")
	}

	app, hooks := newRouterWithHooks(cfg, database, rdb, geoDbs, emailClient, planRegistry, provClient, nrApp)

	slog.Info("server.starting",
		"port", cfg.Port,
		"environment", cfg.Environment,
		"commit_id", buildinfo.GitSHA,
		"build_time", buildinfo.BuildTime,
		"version", buildinfo.Version,
	)
	if err := serveFunc(app, ":"+cfg.Port, gracefulShutdownTimeout, hooks); err != nil {
		slog.Error("server.fatal", "error", err)
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// gracefulShutdownTimeout is the budget Fiber gets to drain in-flight requests
// after SIGTERM. The Kubernetes Deployment sets terminationGracePeriodSeconds
// to 35s; we leave a 5s margin so a stuck shutdown does not collide with
// SIGKILL. Mirror of the provisioner's 5s healthz drain + grpc.GracefulStop —
// the api needs more because its longest in-flight request is a multi-minute
// provision.
const gracefulShutdownTimeout = 25 * time.Second

// readinessDrainGrace is the window held open AFTER MarkDraining flips
// /readyz to 503 and BEFORE we stop accepting new connections. Lets the
// kubelet's readinessProbe tick observe the 503 and pull the pod from
// the Service endpoint list. Pairs with the container preStop hook
// (`sleep 5`) in infra/k8s/app.yaml — two belt-and-braces buffers for
// the same LB-staleness race.
//
// Budget: readinessDrainGrace (3s) + gracefulShutdownTimeout (25s) +
// slack (~2s) ≈ 30s; manifest terminationGracePeriodSeconds=35 leaves a
// 5s safety margin before SIGKILL.
const readinessDrainGrace = 3 * time.Second

// runServerWithGracefulShutdown is the MR-P0-7 fix (BugBash 2026-05-20):
// before this, `app.Listen(":"+cfg.Port)` blocked with no signal handler,
// so SIGTERM (every rolling deploy, every HPA scale-down, every node drain)
// killed the process immediately — RSTing every in-flight request including
// multi-minute provisions. Now we:
//
//  1. Serve in a goroutine so main() can also wait on SIGINT/SIGTERM.
//  2. Trap SIGTERM (kubelet sends it before SIGKILL).
//  3. Flip /readyz to 503 via hooks.Readyz.MarkDraining so the kubelet's
//     readinessProbe pulls the pod from the Service endpoint list.
//  4. Sleep readinessDrainGrace (~3s) so the readinessProbe has a chance
//     to tick before we stop accepting new connections.
//  5. Call app.ShutdownWithTimeout to drain in-flight handlers within the
//     pod's terminationGracePeriodSeconds.
//
// Returns a non-nil error only when the serve goroutine reports a fatal
// listener error (port bind failure etc.) or ShutdownWithTimeout's drain
// budget expires on a stuck request; a clean shutdown via SIGTERM returns
// nil. Extracted as a free function so unit tests can verify the
// drain contract (TestRunServerWithGracefulShutdown_DrainsInflight,
// TestRunServerWithGracefulShutdown_MarksReadinessDraining,
// TestRunServerWithGracefulShutdown_TimeoutKillsStuckRequest).
func runServerWithGracefulShutdown(app *fiber.App, addr string, shutdownTimeout time.Duration, hooks router.ShutdownHooks) error {
	serveErr := make(chan error, 1)
	go func() {
		// Listener errors include ErrServerClosed when ShutdownWithTimeout
		// fires; we swallow that here and surface only genuine fatal errors.
		if err := app.Listen(addr); err != nil && !errors.Is(err, net.ErrClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case sErr := <-serveErr:
		// Listener returned before any signal — bind failure or comparable
		// fatal error. Surface it to main() so the pod CrashLoopBackoffs
		// instead of going green with no listener.
		return sErr
	case <-ctx.Done():
		slog.Info("server.shutdown_signal_received",
			"timeout_seconds", int(shutdownTimeout.Seconds()),
			"readiness_drain_grace_seconds", int(readinessDrainGrace.Seconds()),
		)
	}

	// Phase A: flip /readyz → 503. The kubelet's readinessProbe will
	// observe the 503 on its next tick and pull the pod from the
	// Service endpoint list. The preStop `sleep 5` in infra/k8s/app.yaml
	// already guarantees an LB-update window before SIGTERM is delivered;
	// this is the in-process belt to that hook's braces.
	if hooks.Readyz != nil {
		hooks.Readyz.MarkDraining()
		slog.Info("server.readiness_marked_draining")
	}

	// Phase B: sleep readinessDrainGrace so a probe tick (and an LB
	// endpoint refresh) can land before we stop accepting connections.
	time.Sleep(readinessDrainGrace)

	// Phase C: drain in-flight requests within shutdownTimeout. Fiber's
	// ShutdownWithTimeout stops accepting new connections and waits for
	// existing handlers to finish (up to the timeout) before returning.
	// A timeout returns a non-nil error which we surface to main() — the
	// process still exits cleanly, but the operator can grep
	// server.graceful_shutdown_failed for stuck-request audits.
	if err := app.ShutdownWithTimeout(shutdownTimeout); err != nil {
		slog.Error("server.graceful_shutdown_failed", "error", err)
		return err
	}

	// Wait for the Listen goroutine to fully exit so we don't race a still-
	// running serve loop with main()'s defers (telemetry, NR app shutdown,
	// DB pool close).
	if sErr := <-serveErr; sErr != nil {
		slog.Warn("server.serve_exit_after_shutdown", "error", sErr)
	}
	slog.Info("server.graceful_shutdown_complete")
	return nil
}

// initNewRelic constructs the NR Go agent. Returns nil (and logs a
// single warning) when the license key is empty so the rest of the
// process boots normally — fail-open is the contract for every
// observability dependency in this codebase.
//
// The app name is derived from NEW_RELIC_APP_NAME when set, otherwise
// "instant-<service>" matching the convention in the design doc
// (instant-api, instant-worker, instant-provisioner).
func initNewRelic(service string) *newrelic.Application {
	license := os.Getenv("NEW_RELIC_LICENSE_KEY")
	if license == "" {
		slog.Warn("newrelic.disabled", "reason", "NEW_RELIC_LICENSE_KEY not set")
		return nil
	}
	appName := os.Getenv("NEW_RELIC_APP_NAME")
	if appName == "" {
		appName = "instant-" + service
	}
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName(appName),
		newrelic.ConfigLicense(license),
		newrelic.ConfigDistributedTracerEnabled(true),
		// AppLogForwardingEnabled is intentionally left at the default
		// (false). Forwarding via the agent doubles ingest cost; logs
		// already ship via stdout → kube → log shipper. The slog
		// handler stamps commit_id / trace_id so NR's log-trace join
		// works without agent forwarding.
	)
	if err != nil {
		// init failed (network, malformed license, etc.) — log and
		// continue with a nil app. The middleware no-ops on nil.
		slog.Error("newrelic.init_failed", "error", err)
		return nil
	}
	slog.Info("newrelic.initialized", "app_name", appName)
	return app
}

// envProduction is the cfg.Environment value that flips loadPlansRegistry
// from "warn + fallback" to "fail-loud". Matches the string the rest of
// the codebase compares against (router policy gates, dev-only routes,
// etc.). Hoisted to a constant so the comparison isn't a magic string
// at each callsite.
const envProduction = "production"

// loadPlansRegistry loads the plans.yaml file at path. Behaviour by env:
//
//   - production: a load failure is FATAL. Returns (nil, err) so main()
//     can log + os.Exit(1). Falling back to common/plans.Default() in
//     production would silently serve stale limits/pricing because
//     plans.yaml is the declared single source of truth (per CLAUDE.md).
//     A configmap drift or missing volume mount must surface as
//     CrashLoopBackoff, not a green /healthz with wrong limits.
//
//   - any other environment (development / staging / test): a load
//     failure logs slog.Warn("plans.file_not_found") with path + env
//     and returns the embedded Default() registry so local `make run`
//     keeps working without an on-disk plans.yaml. The warn key matches
//     the existing NR alert rule on plans.file_not_found, so configmap
//     drift in staging trips the same alert pipeline production would.
//
// Extracted as a free function so unit tests can pin both branches of
// the contract (TestLoadPlansRegistry_ProductionFatal /
// TestLoadPlansRegistry_DevFallsBack in main_test.go) without spinning
// up main().
func loadPlansRegistry(path, env string) (*plans.Registry, error) {
	registry, err := plans.Load(path)
	if err == nil {
		return registry, nil
	}
	if env == envProduction {
		return nil, fmt.Errorf("plans.Load %q in production: %w", path, err)
	}
	// Dev / staging / test: warn loudly so configmap drift in staging
	// trips the existing NR alert on plans.file_not_found, but keep
	// booting against the embedded defaults. The slog key matches what
	// the alert rule queries — do not rename without coordinating with
	// the dashboard query.
	slog.Warn("plans.file_not_found",
		"error", err,
		"path", path,
		"env", env,
		"fallback", "embedded_defaults",
	)
	return plans.Default(), nil
}

// imageDigestEnvVar names the env var Kubernetes populates via
// `valueFrom.fieldRef: fieldPath: status.containerStatuses[0].imageID`.
// The Deployment spec for the api service wires this in so the pod
// learns its own image digest at boot. Unset → local-build fallback so
// `make run` doesn't have to fake a sha256 string.
const imageDigestEnvVar = "IMAGE_DIGEST"

// imageDigestFallback is what we record when IMAGE_DIGEST is not in the
// environment. Treated as a normal value at the DB layer — the unique
// index works fine on the literal string. The point is that local
// dev / CI / smoke-test boots all collapse onto one row instead of
// being randomly attributed.
const imageDigestFallback = "local-build"

// resolveImageDigest returns the value of the IMAGE_DIGEST env var with
// surrounding whitespace trimmed, or imageDigestFallback if the var is
// unset or empty. Extracted as a pure function so unit tests can pin the
// "unset → local-build" contract without spinning up a real DB.
func resolveImageDigest() string {
	if v := strings.TrimSpace(os.Getenv(imageDigestEnvVar)); v != "" {
		return v
	}
	return imageDigestFallback
}

// emitDeployAuditSelfReport writes one row to deploys_audit reporting
// the running binary's identity (service name + commit + image digest +
// version + build time). Idempotent via the table's ON CONFLICT clause:
// the first pod of a given image writes the row, every subsequent pod
// of the same image is a no-op.
//
// Best-effort: a DB error here is logged at WARN and swallowed. The
// audit row is observability — it must never block startup.
//
// The "migration_version" column is left empty here; the value would
// have to come from peeking at the embedded migration FS at boot. We
// can populate it in a follow-up if we ever need it operationally.
// Right now the (service, commit, digest) tuple is enough to answer
// "what was running."
func emitDeployAuditSelfReport(database *sql.DB) {
	digest := resolveImageDigest()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := models.InsertSelfReport(ctx, database, models.SelfReportParams{
		Service:     "api",
		CommitID:    buildinfo.GitSHA,
		ImageDigest: digest,
		Version:     buildinfo.Version,
		BuildTime:   buildinfo.BuildTime,
	}); err != nil {
		slog.Warn("deploys_audit.self_report_failed", "error", err,
			"service", "api", "commit_id", buildinfo.GitSHA, "image_digest", digest)
		return
	}
	slog.Info("deploys_audit.self_report",
		"service", "api", "commit_id", buildinfo.GitSHA, "image_digest", digest,
		"version", buildinfo.Version, "build_time", buildinfo.BuildTime)
}

