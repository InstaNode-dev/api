// TODO(obs-merge): replace obsstubs imports with common/buildinfo and
// common/logctx once Tracks 1 + 2 of the observability rollout land on
// master. The stubs at internal/obsstubs/{buildinfo,logctx} match the
// exported surface of those packages 1:1; the merge agent should rewrite
// the import paths and delete the obsstubs directory.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

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

func main() {
	// Structured JSON logging — wrapped in logctx.Handler so every record
	// is decorated with service, commit_id, trace_id, team_id, tid.
	//
	// AddSource gives file:line of the slog call site (caller field in
	// the design doc). Done before any other slog call in main so even
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

	shutdownTracer := telemetry.InitTracer("instant-api", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
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

	database := db.ConnectPostgres(cfg.DatabaseURL)
	defer database.Close()

	if err := db.RunMigrations(database); err != nil {
		slog.Error("main.migrations_failed", "error", err)
		os.Exit(1)
	}

	// Deploy-audit self-report. Idempotent on (service, commit_id,
	// image_digest) — every pod startup of the same image is a no-op
	// at the DB level, so a 10-replica autoscale or a routine restart
	// writes at most one row. Failures here are non-fatal: this is
	// observability, not a correctness gate, and a DB hiccup on boot
	// must not stop the server from listening.
	emitDeployAuditSelfReport(database)

	rdb := db.ConnectRedis(cfg.RedisURL)
	defer rdb.Close()

	geoDbs := middleware.LoadGeoLite2(cfg.GeoLite2DBPath)
	if geoDbs != nil && geoDbs.City != nil {
		defer geoDbs.City.Close()
	}
	if geoDbs != nil && geoDbs.ASN != nil {
		defer geoDbs.ASN.Close()
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
		os.Exit(1)
	}

	var provClient *provisioner.Client
	if cfg.ProvisionerAddr != "" {
		var conn *grpc.ClientConn
		provClient, conn, err = provisioner.NewClient(cfg.ProvisionerAddr, cfg.ProvisionerSecret)
		if err != nil {
			slog.Error("main.provisioner_connect_failed", "error", err)
			os.Exit(1)
		}
		defer conn.Close()
		slog.Info("main.provisioner_connected", "addr", cfg.ProvisionerAddr)
	} else {
		slog.Info("main.provisioner_local", "note", "PROVISIONER_ADDR not set, using local providers")
	}

	app := router.New(cfg, database, rdb, geoDbs, emailClient, planRegistry, provClient, nrApp)

	slog.Info("server.starting",
		"port", cfg.Port,
		"environment", cfg.Environment,
		"commit_id", buildinfo.GitSHA,
		"build_time", buildinfo.BuildTime,
		"version", buildinfo.Version,
	)
	if err := app.Listen(":" + cfg.Port); err != nil {
		slog.Error("server.fatal", "error", err)
		os.Exit(1)
	}
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

