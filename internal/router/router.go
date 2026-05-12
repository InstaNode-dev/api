package router

import (
	"database/sql"
	"errors"
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
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/k8s"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
)

// New creates and configures the Fiber application with all middleware and routes registered.
func New(cfg *config.Config, db *sql.DB, rdb *redis.Client, geoDbs *middleware.GeoDBs, emailClient *email.Client, planRegistry *plans.Registry, provClient *provisioner.Client) *fiber.App {
	app := fiber.New(fiber.Config{
		// Disable default error handler — we write our own JSON errors
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// respondError already wrote the body — must not overwrite, or
			// every 400/403/etc. becomes a 500 "internal_error" via the
			// generic path below. See handlers.ErrResponseWritten.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
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
		// Production origin (GitHub Pages serves instanode.dev) + every
		// reasonable local-dev port. The wildcard would still work for
		// bearer-token traffic (no cookies in flight) but an explicit
		// allowlist makes the policy auditable. Add origins as needed.
		AllowOrigins:  "https://instanode.dev,https://www.instanode.dev,http://localhost:5173,http://localhost:3000,http://localhost:5174",
		AllowMethods:  "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:  "Content-Type,Authorization,X-Request-ID,X-E2E-Test-Token,X-E2E-Source-IP",
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
	if cfg.ObjectStoreEndpoint != "" {
		backend := storageprovider.Backend(cfg.ObjectStoreBackend)
		if sp, err := storageprovider.NewWithBackend(
			backend,
			cfg.ObjectStoreEndpoint,
			cfg.ObjectStorePublicURL,
			cfg.ObjectStoreAccessKey,
			cfg.ObjectStoreSecretKey,
			cfg.ObjectStoreBucket,
			cfg.ObjectStoreSecure,
		); err != nil {
			slog.Warn("storage: provider init failed", "backend", backend, "error", err)
		} else {
			slog.Info("storage: provider initialized", "backend", backend, "endpoint", cfg.ObjectStoreEndpoint)
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

	// Custom-domain handler shares the k8s stack provider so EnsureCustomDomainIngress
	// can update the same Ingress namespace the stack lives in. We construct a
	// dedicated *k8s.K8sStackProvider here (rather than reaching into stackH) so
	// the dependency surface stays explicit. When ComputeProvider != "k8s" the
	// pointer is left nil and the handler skips ingress work — verification still
	// progresses through TXT and the row stays at "verified" / "ingress_ready"
	// until a future operator wires real k8s.
	var customDomainK8s handlers.CustomDomainProvider
	if cfg.ComputeProvider == "k8s" {
		// Custom-domain reconciliation doesn't trigger builds, so an empty
		// BuildContextConfig is fine — the upload path is never reached here.
		if csp, err := k8s.NewStackProvider(cfg.KubeNamespaceApps, k8s.BuildContextConfig{}); err != nil {
			slog.Warn("custom_domain.k8s_provider_unavailable", "error", err)
		} else {
			customDomainK8s = csp
		}
	}
	customDomainH := handlers.NewCustomDomainHandler(db, cfg, planRegistry, customDomainK8s)

	// ── Routes ───────────────────────────────────────────────────────────────

	// Health check
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true, "service": "instant.dev"})
	})

	// OpenAPI spec — machine-readable description of the agent-facing API
	app.Get("/openapi.json", handlers.ServeOpenAPI)

	// MCP authorization profile — RFC 8414 / OAuth 2.0 Protected Resource Metadata.
	app.Get("/.well-known/oauth-protected-resource", handlers.ServeOAuthProtectedResourceMetadata)

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

	// OAuth — POST handler serves the existing programmatic / SPA flow.
	// Google login is intentionally NOT supported; if you need it, register
	// the routes here and wire GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET.
	app.Post("/auth/github", authH.GitHub)

	// Browser OAuth flows (GET-based, redirect-driven). The dashboard's
	// login page links to /auth/github/start directly; it stashes a CSRF
	// state cookie, hands off to GitHub, and 302s back to
	// <return_to>?session_token=<jwt> after exchanging the code.
	app.Get("/auth/github/start", authH.GitHubStart)
	app.Get("/auth/github/callback", authH.GitHubCallback)

	// Magic-link email login. Start is POST (the dashboard's login form
	// submits to it); Callback is GET (the user's email client links to it).
	mlH := handlers.NewMagicLinkHandler(db, cfg, emailClient, authH)
	app.Post("/auth/email/start", mlH.Start)
	app.Get("/auth/email/callback", mlH.Callback)

	// CLI device-flow login — POST creates session, GET polls for completion
	app.Post("/auth/cli", cliAuthH.CreateCLISession)
	app.Get("/auth/cli/:id", cliAuthH.PollCLISession)
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	// Billing
	billing := handlers.NewBillingHandler(db, cfg, emailClient)
	// Legacy alias kept for backward compatibility; canonical path is
	// /api/v1/billing/checkout (registered under the /api/v1 group below).
	app.Post("/billing/checkout", middleware.RequireAuth(cfg), billing.CreateCheckoutAPI)
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	// §10.20 cached-aggregation endpoints. Separate handlers from BillingHandler
	// so the caching contract (Redis + singleflight + Cache-Control headers)
	// is visible at the route + handler boundary, not buried inside the billing
	// state aggregator. Wired below under the /api/v1 group.
	billingUsageH := handlers.NewBillingUsageHandler(db, rdb, planRegistry)
	teamSummaryH := handlers.NewTeamSummaryHandler(db, rdb, planRegistry)

	// Public webhook request listing — token IS the credential (no session needed).
	// Authenticated callers use the same handler; it additionally verifies team ownership.
	app.Get("/api/v1/webhooks/:token/requests", middleware.OptionalAuth(cfg), webhookH.ListRequests)

	// Public token-based invitation accept — must be registered BEFORE the
	// /api/v1 auth group so the group middleware doesn't catch it.
	// (Token IS the auth here — no Bearer required.)
	teamsHPublic := handlers.NewTeamsHandler(db, cfg, emailClient)
	app.Post("/api/v1/invitations/:token/accept", teamsHPublic.AcceptInvitation)

	// Authenticated resource management
	middleware.SetRoleLookupDB(db) // populate auth_team_role on every RequireAuth
	middleware.SetAPIKeyDB(db)     // enable PAT auth path in RequireAuth
	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())

	// /whoami — identity probe for agents. Returning 401 here is the canonical
	// "your token is bad"; returning anything else from this endpoint means
	// the token works. Reaching for arbitrary paths like /api/v1/team gave
	// 404 instead of 401, leading to wasted token-mint retry cycles.
	whoamiH := handlers.NewWhoamiHandler(db)
	api.Get("/whoami", whoamiH.Get)

	api.Get("/resources", resourceH.List)
	api.Get("/resources/:id", resourceH.Get)
	api.Get("/resources/:id/credentials", resourceH.GetCredentials)
	api.Delete("/resources/:id", resourceH.Delete)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)

	api.Get("/team/members", teamMembersH.ListMembers)
	api.Post("/team/members/invite", teamMembersH.InviteMember)
	api.Post("/team/members/leave", teamMembersH.LeaveTeam)
	api.Delete("/team/members/:user_id", teamMembersH.RemoveMember)
	api.Get("/team/invitations", teamMembersH.ListInvitations)
	api.Delete("/team/invitations/:id", teamMembersH.RevokeInvitation)
	api.Post("/team/invitations/:id/accept", teamMembersH.AcceptInvitation)

	api.Get("/billing", billing.GetBillingState)
	api.Post("/billing/checkout", billing.CreateCheckoutAPI)
	api.Post("/billing/cancel", billing.CancelSubscriptionAPI)
	api.Get("/billing/invoices", billing.ListInvoicesAPI)
	api.Post("/billing/update-payment", billing.UpdatePaymentMethodAPI)
	api.Post("/billing/change-plan", billing.ChangePlanAPI)

	// §10.20 cached aggregates — see billing_usage.go / team_summary.go.
	// Both cache per-team in Redis (30s / 5min) with singleflight + Cache-Control
	// response headers. The dashboard's BillingPage + SidebarUpgradeCard
	// consume these instead of computing aggregates client-side.
	api.Get("/billing/usage", billingUsageH.GetUsage)
	api.Get("/team/summary", teamSummaryH.GetSummary)

	// Deploy management endpoints — Phase 6 (aliases under /api/v1)
	api.Get("/deployments", deployH.List)
	api.Get("/deployments/:id", deployH.Get)
	api.Delete("/deployments/:id", deployH.Delete)

	// Stack management endpoints — Phase 6 (under /api/v1)
	api.Get("/stacks", stackH.List)

	// Env promotion — Pro+ "promote staging → production" + sibling envs.
	// Tier gate (pro/team/growth) is enforced inside the handler so the
	// router doesn't have to know the policy.
	api.Post("/stacks/:slug/promote", stackH.Promote)

	// Custom domains — Pro+ "bring your own hostname" for stacks. All routes
	// require auth (the /api/v1 group middleware) and additionally enforce
	// stack ownership inside the handler.
	api.Post("/stacks/:slug/domains", customDomainH.Create)
	api.Get("/stacks/:slug/domains", customDomainH.List)
	api.Post("/stacks/:slug/domains/:id/verify", customDomainH.Verify)
	api.Delete("/stacks/:slug/domains/:id", customDomainH.Delete)

	// Personal Access Tokens — long-lived bearer tokens for agents/CI.
	apiKeysH := handlers.NewAPIKeysHandler(db)
	api.Post("/auth/api-keys", apiKeysH.Create)
	api.Get("/auth/api-keys", apiKeysH.List)
	api.Delete("/auth/api-keys/:id", apiKeysH.Revoke)

	// Per-team audit log — feeds the dashboard's Recent Activity panel.
	auditH := handlers.NewAuditHandler(db)
	api.Get("/audit", auditH.List)

	// Vault — per-team encrypted secret storage (Phase 1: Heroku-shape platform).
	vaultH := handlers.NewVaultHandler(db, cfg, planRegistry)
	api.Put("/vault/:env/:key", vaultH.PutSecret)
	api.Get("/vault/:env/:key", vaultH.GetSecret)
	api.Get("/vault/:env", vaultH.ListKeys)
	api.Delete("/vault/:env/:key", vaultH.DeleteSecret)
	api.Post("/vault/:env/:key/rotate", vaultH.RotateSecret)
	// Vault env-to-env bulk copy (Pro+ tier-gated inside the handler) —
	// pairs with POST /api/v1/stacks/:slug/promote for the dashboard's
	// "promote staging → production" flow.
	api.Post("/vault/copy", vaultH.CopySecrets)

	// Teams + RBAC invitation flow (Phase 3). Public accept route is
	// registered above the api group so the auth middleware doesn't catch it.
	teamsH := teamsHPublic // reuse the same handler instance
	api.Post("/teams/:team_id/invitations", middleware.RequireRole("admin"), teamsH.CreateInvitation)
	api.Get("/teams/:team_id/invitations", middleware.RequireRole("admin"), teamsH.ListInvitations)
	api.Delete("/teams/:team_id/invitations/:id", middleware.RequireRole("admin"), teamsH.RevokeInvitation)

	// Internal dev-only endpoints — only registered in development environment.
	// These bypass Razorpay and directly mutate DB state. Never expose in production.
	if cfg.Environment == "development" {
		internal := app.Group("/internal")
		internal.Post("/set-tier", handlers.NewSetTierHandler(db, cfg.AESKey))
	}

	return app
}
