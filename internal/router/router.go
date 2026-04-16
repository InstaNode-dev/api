package router

import (
	"database/sql"
	"log/slog"

	"github.com/gofiber/contrib/otelfiber/v2"
	"github.com/gofiber/fiber/v2"
	fiberCORS "github.com/gofiber/fiber/v2/middleware/cors"
	fiberRecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/migratorclient"
	"instant.dev/internal/plans"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
)

// New creates and configures the Fiber application with all middleware and routes registered.
func New(cfg *config.Config, db *sql.DB, rdb *redis.Client, geoDbs *middleware.GeoDBs, emailClient *email.Client, planRegistry *plans.Registry, provClient *provisioner.Client) *fiber.App {
	app := fiber.New(fiber.Config{
		// Disable default error handler — we write our own JSON errors
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			var errKey, msg string
			switch code {
			case fiber.StatusNotFound:
				errKey, msg = "not_found", "The requested resource was not found"
			case fiber.StatusMethodNotAllowed:
				errKey, msg = "method_not_allowed", "Method not allowed"
			default:
				errKey, msg = "internal_error", "An unexpected error occurred"
			}
			return c.Status(code).JSON(fiber.Map{
				"ok":      false,
				"error":   errKey,
				"message": msg,
			})
		},
		// Trust proxy headers for real IPs (adjust in production to specific trusted proxies)
		ProxyHeader: "X-Forwarded-For",
	})

	// ── Middleware chain (order matters) ─────────────────────────────────────
	app.Use(middleware.RequestID())
	app.Use(otelfiber.Middleware())
	// Telemetry must come before Recover so that panic-induced 500s are recorded.
	app.Use(middleware.Telemetry())
	app.Use(fiberRecover.New(fiberRecover.Config{
		EnableStackTrace: cfg.Environment == "development",
	}))
	app.Use(fiberCORS.New(fiberCORS.Config{
		AllowOrigins:  "*",
		AllowMethods:  "GET,POST,PATCH,DELETE,OPTIONS",
		AllowHeaders:  "Content-Type,Authorization,X-Request-ID",
		ExposeHeaders: "X-Request-ID,X-Instant-Upgrade,X-Instant-Notice",
	}))
	app.Use(middleware.GeoEnrich(geoDbs))
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{
		Limit:     100,
		KeyPrefix: "rl",
	}))

	// ── Handlers ─────────────────────────────────────────────────────────────
	onboardH := handlers.NewOnboardingHandler(db, cfg, emailClient)
	authH := handlers.NewAuthHandler(db, cfg)
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planRegistry)
	// Build storage provider once and share it with both StorageHandler and ResourceHandler
	// so that DELETE /api/v1/resources/:id can deprovision MinIO IAM users.
	var storageProv *storageprovider.Provider
	if cfg.MinioEndpoint != "" {
		if sp, err := storageprovider.New(cfg.MinioEndpoint, cfg.MinioRootUser, cfg.MinioRootPassword, cfg.MinioBucketName); err != nil {
			slog.Warn("storage: MinIO provider init failed", "error", err)
		} else {
			storageProv = sp
		}
	}

	resourceH := handlers.NewResourceHandler(db, rdb, cfg, planRegistry, provClient, storageProv)
	teamMembersH := handlers.NewTeamMembersHandler(db, cfg, planRegistry, emailClient)
	dbH := handlers.NewDBHandler(db, rdb, cfg, provClient, planRegistry)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, provClient, planRegistry)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, provClient, planRegistry)
	queueH := handlers.NewQueueHandler(db, rdb, cfg, provClient, planRegistry)
	storageH := handlers.NewStorageHandler(db, rdb, cfg, storageProv, planRegistry)
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, planRegistry)
	logsH := handlers.NewLogsHandler(db)
	deployH := handlers.NewDeployHandler(db, rdb, cfg)
	stackH := handlers.NewStackHandler(db, rdb, cfg, planRegistry)

	// ── Routes ───────────────────────────────────────────────────────────────

	// Health check
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "service": "instant.dev"})
	})

	// OpenAPI spec — machine-readable description of the agent-facing API
	app.Get("/openapi.json", handlers.ServeOpenAPI)

	// Prometheus metrics — gated by METRICS_TOKEN when set (open in local dev).
	app.Get("/metrics", func(c *fiber.Ctx) error {
		if cfg.MetricsToken != "" {
			auth := c.Get("Authorization")
			if auth != "Bearer "+cfg.MetricsToken {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"ok": false, "error": "unauthorized"})
			}
		}
		fasthttpadaptor.NewFastHTTPHandler(promhttp.Handler())(c.Context())
		return nil
	})

	// Onboarding / upgrade flow
	app.Get("/start", onboardH.StartLanding)
	app.Get("/claim/preview", onboardH.ClaimPreview)
	app.Post("/claim", onboardH.Claim)

	// Provisioning — Phase 2+ (gated by IsServiceEnabled in each handler)
	// OptionalAuth is registered per-route rather than via app.Group("/", ...) to avoid
	// accidentally applying it globally to all routes (Fiber's "/" group prefix matches everything).
	app.Post("/db/new", middleware.OptionalAuth(cfg), dbH.NewDB)
	app.Post("/cache/new", middleware.OptionalAuth(cfg), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuth(cfg), nosqlH.NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuth(cfg), queueH.NewQueue)
	app.Post("/storage/new", middleware.OptionalAuth(cfg), storageH.NewStorage)
	app.Post("/webhook/new", middleware.OptionalAuth(cfg), webhookH.NewWebhook)
	app.Post("/webhook/receive/:token", webhookH.Receive)
	app.Get("/resources/:token/logs", logsH.ResourceLogs)

	// Deploy — Phase 6 (auth required on all endpoints)
	deployGroup := app.Group("/deploy", middleware.RequireAuth(cfg))
	deployGroup.Post("/new", deployH.New)
	deployGroup.Get("/:id", deployH.Get)
	deployGroup.Get("/:id/logs", deployH.Logs)
	deployGroup.Patch("/:id/env", deployH.UpdateEnv)
	deployGroup.Delete("/:id", deployH.Delete)
	deployGroup.Post("/:id/redeploy", deployH.Redeploy)

	// Stacks — Phase 6 multi-service.
	// New/Get/Logs/Delete use OptionalAuth (anonymous stacks supported, same as /db/new etc.).
	// UpdateEnv/Redeploy require auth (mutations on owned stacks).
	app.Post("/stacks/new", middleware.OptionalAuth(cfg), stackH.New)
	app.Get("/stacks/:slug", middleware.OptionalAuth(cfg), stackH.Get)
	app.Get("/stacks/:slug/logs/:svc", middleware.OptionalAuth(cfg), stackH.Logs)
	app.Delete("/stacks/:slug", middleware.OptionalAuth(cfg), stackH.Delete)
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), stackH.UpdateEnv)
	app.Post("/stacks/:slug/redeploy", middleware.RequireAuth(cfg), stackH.Redeploy)

	// OAuth
	app.Post("/auth/github", authH.GitHub)
	app.Post("/auth/google", authH.Google)
	app.Post("/auth/google/callback", authH.GoogleCallback)
	app.Get("/auth/google/url", authH.GoogleAuthURL)

	// CLI device-flow login — POST creates session, GET polls for completion
	app.Post("/auth/cli", cliAuthH.CreateCLISession)
	app.Get("/auth/cli/:id", cliAuthH.PollCLISession)
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	// Billing
	var migClient *migratorclient.Client
	if cfg.MigratorAddr != "" {
		migClient = migratorclient.New(cfg.MigratorAddr, cfg.MigratorSecret)
	}
	billing := handlers.NewBillingHandler(db, cfg, emailClient, migClient)
	app.Post("/billing/checkout", middleware.RequireAuth(cfg), billing.CreateCheckout)
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	// Public webhook request listing — token IS the credential (no session needed).
	// Authenticated callers use the same handler; it additionally verifies team ownership.
	app.Get("/api/v1/webhooks/:token/requests", middleware.OptionalAuth(cfg), webhookH.ListRequests)

	// Authenticated resource management
	api := app.Group("/api/v1", middleware.RequireAuth(cfg))
	api.Get("/resources", resourceH.List)
	api.Get("/resources/:id", resourceH.Get)
	api.Delete("/resources/:id", resourceH.Delete)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)

	api.Get("/team/members", teamMembersH.ListMembers)
	api.Post("/team/members/invite", teamMembersH.InviteMember)
	api.Post("/team/members/leave", teamMembersH.LeaveTeam)
	api.Delete("/team/members/:user_id", teamMembersH.RemoveMember)
	api.Get("/team/invitations", teamMembersH.ListInvitations)
	api.Delete("/team/invitations/:id", teamMembersH.RevokeInvitation)
	api.Post("/team/invitations/:id/accept", teamMembersH.AcceptInvitation)

	api.Post("/billing/cancel", billing.CancelSubscriptionAPI)
	api.Get("/billing/invoices", billing.ListInvoicesAPI)
	api.Post("/billing/update-payment", billing.UpdatePaymentMethodAPI)
	api.Post("/billing/change-plan", billing.ChangePlanAPI)

	// Deploy management endpoints — Phase 6 (aliases under /api/v1)
	api.Get("/deployments", deployH.List)
	api.Get("/deployments/:id", deployH.Get)
	api.Delete("/deployments/:id", deployH.Delete)

	// Stack management endpoints — Phase 6 (under /api/v1)
	api.Get("/stacks", stackH.List)

	// Internal dev-only endpoints — only registered in development environment.
	// These bypass Razorpay and directly mutate DB state. Never expose in production.
	if cfg.Environment == "development" {
		internal := app.Group("/internal")
		internal.Post("/set-tier", handlers.NewSetTierHandler(db, cfg.AESKey, migClient))
	}

	return app
}
