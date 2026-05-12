// TODO(obs-merge): replace obsstubs imports with common/buildinfo and
// common/logctx once Tracks 1 + 2 of the observability rollout land on
// master. The stubs at internal/obsstubs/{buildinfo,logctx} match the
// exported surface of those packages 1:1; the merge agent should rewrite
// the import paths and delete the obsstubs directory.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/newrelic/go-agent/v3/newrelic"
	"google.golang.org/grpc"
	"instant.dev/common/buildinfo"
	"instant.dev/common/logctx"
	"instant.dev/internal/config"
	"instant.dev/internal/db"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
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
	slog.SetDefault(slog.New(logctx.NewHandler(serviceName, base)))

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

	database := db.ConnectPostgres(cfg.DatabaseURL)
	defer database.Close()

	if err := db.RunMigrations(database); err != nil {
		slog.Error("main.migrations_failed", "error", err)
		os.Exit(1)
	}

	rdb := db.ConnectRedis(cfg.RedisURL)
	defer rdb.Close()

	geoDbs := middleware.LoadGeoLite2(cfg.GeoLite2DBPath)
	if geoDbs != nil && geoDbs.City != nil {
		defer geoDbs.City.Close()
	}
	if geoDbs != nil && geoDbs.ASN != nil {
		defer geoDbs.ASN.Close()
	}

	emailClient := email.New(cfg.ResendAPIKey)

	plansPath := os.Getenv("PLANS_PATH")
	if plansPath == "" {
		plansPath = "plans.yaml"
	}
	planRegistry, err := plans.Load(plansPath)
	if err != nil {
		slog.Warn("plans file not found or invalid — using built-in defaults", "error", err, "path", plansPath)
		planRegistry = plans.Default()
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
