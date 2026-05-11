package main

import (
	"context"
	"log/slog"
	"os"

	"google.golang.org/grpc"
	"instant.dev/internal/config"
	"instant.dev/internal/db"
	"instant.dev/internal/email"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/router"
	"instant.dev/internal/telemetry"
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

	slog.Info("server.starting", "port", cfg.Port, "environment", cfg.Environment)
	if err := app.Listen(":" + cfg.Port); err != nil {
		slog.Error("server.fatal", "error", err)
		os.Exit(1)
	}
}
