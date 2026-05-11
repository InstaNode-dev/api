package main

import (
	"context"
	"log/slog"
	"net"
	"os"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"instant.dev/internal/config"
	"instant.dev/internal/dashboardsvc"
	"instant.dev/internal/db"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	compute "instant.dev/internal/providers/compute"
	"instant.dev/internal/providers/compute/k8s"
	"instant.dev/internal/providers/compute/noop"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/router"
	"instant.dev/internal/telemetry"
	dashboardv1 "instant.dev/proto/dashboard/v1"
)

func main() {
	// Structured JSON logging
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	shutdownTracer := telemetry.InitTracer("instant-api", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	defer func() {
		if err := shutdownTracer(context.Background()); err != nil {
			slog.Error("telemetry.shutdown_failed", "error", err)
		}
	}()

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

	app := router.New(cfg, database, rdb, geoDbs, emailClient, planRegistry, provClient)

	var storageProv *storageprovider.Provider
	if cfg.MinioEndpoint != "" {
		if sp, err := storageprovider.New(cfg.MinioEndpoint, cfg.MinioPublicEndpoint, cfg.MinioRootUser, cfg.MinioRootPassword, cfg.MinioBucketName); err != nil {
			slog.Warn("dashboard_grpc: MinIO provider init failed", "error", err)
		} else {
			storageProv = sp
		}
	}

	var stackProv compute.StackProvider
	if cfg.ComputeProvider == "k8s" {
		ksp, err := k8s.NewStackProvider(cfg.KubeNamespaceApps)
		if err != nil {
			slog.Warn("dashboard_grpc.stack_k8s_unavailable", "error", err)
			stackProv = noop.NewStack()
		} else {
			stackProv = ksp
		}
	} else {
		stackProv = noop.NewStack()
	}

	dashSvc := dashboardsvc.NewServer(database, rdb, cfg, planRegistry, provClient, storageProv, emailClient, stackProv)
	grpcServer := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.UnaryInterceptor(dashboardsvc.AuthInterceptor(cfg.JWTSecret)),
	)
	dashboardv1.RegisterDashboardServiceServer(grpcServer, dashSvc)

	grpcLis, err := net.Listen("tcp", ":50052")
	if err != nil {
		slog.Error("dashboard_grpc.listen_failed", "error", err)
		os.Exit(1)
	}
	go func() {
		slog.Info("dashboard_grpc.starting", "addr", grpcLis.Addr().String())
		if serveErr := grpcServer.Serve(grpcLis); serveErr != nil {
			slog.Error("dashboard_grpc.serve_failed", "error", serveErr)
			os.Exit(1)
		}
	}()

	slog.Info("server.starting", "port", cfg.Port, "environment", cfg.Environment)
	if err := app.Listen(":" + cfg.Port); err != nil {
		slog.Error("server.fatal", "error", err)
		os.Exit(1)
	}
}
