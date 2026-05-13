package router

import (
	"database/sql"
	"errors"
	"log/slog"

	"github.com/gofiber/contrib/otelfiber/v2"
	"github.com/gofiber/fiber/v2"
	fiberCORS "github.com/gofiber/fiber/v2/middleware/cors"
	fiberRecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"instant.dev/common/buildinfo"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/migrations"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/k8s"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/razorpaybilling"
)

// New creates and configures the Fiber application with all middleware and routes registered.
//
// nrApp may be nil — the New Relic Go agent fails open when no license
// key is set (local dev, CI). The NewRelic Fiber middleware degrades to
// a no-op in that case, so the rest of the chain is unaffected.
func New(cfg *config.Config, db *sql.DB, rdb *redis.Client, geoDbs *middleware.GeoDBs, emailClient *email.Client, planRegistry *plans.Registry, provClient *provisioner.Client, nrApp *newrelic.Application) *fiber.App {
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
	// LoggerContext copies request_id (and team_id once auth has run)
	// from Fiber locals onto the Go ctx so every slog call downstream
	// is auto-stamped via the logctx.Handler wrapper. Must follow
	// RequestID; team_id gets stamped on a second pass after auth
	// middleware writes it to locals (LoggerContext also runs once
	// inside the auth-gated groups via middleware.RequireAuth chain).
	app.Use(middleware.LoggerContext())
	app.Use(otelfiber.Middleware())
	// New Relic transaction per request. No-op when nrApp is nil.
	// Sits after otelfiber so the OTel span context is established
	// before NR's StartTransaction (NR's distributed-tracer header
	// extraction reads from the request, not from OTel context, but
	// keeping both before user middleware is the safe order).
	app.Use(middleware.NewRelic(nrApp))
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
	envPolicyH := handlers.NewEnvPolicyHandler(db)
	dbH := handlers.NewDBHandler(db, rdb, cfg, provClient, planRegistry)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, provClient, planRegistry)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, provClient, planRegistry)
	// twinH composes the three above so POST /api/v1/resources/:id/provision-twin
	// dispatches to the same low-level provision pipelines as /db/new etc.
	// Wire AFTER the three constructors so the handler instances exist.
	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)
	queueH := handlers.NewQueueHandler(db, rdb, cfg, provClient, planRegistry)
	storageH := handlers.NewStorageHandler(db, rdb, cfg, storageProv, planRegistry)
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, planRegistry)
	logsH := handlers.NewLogsHandler(db)
	deployH := handlers.NewDeployHandler(db, rdb, cfg, planRegistry)
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

	// Health check — emits buildinfo (so operators / canaries / dashboards
	// can verify which commit is actually running) plus migration state
	// (so the same probe answers "did my migrations apply" alongside "is
	// my image stale"). The migration read is cached for 60s per pod
	// so /healthz stays <10ms p99 under readiness-probe traffic.
	//
	// Uninstrumented binaries return the "dev" sentinel rather than empty
	// strings so the wire shape stays stable. When the DB is unreachable
	// migration_status becomes "unknown" but the response stays 200 — the
	// service is up, only the tracking read failed.
	migrationReader := migrations.NewReader(db, 0, nil)
	app.Get("/healthz", func(c *fiber.Ctx) error {
		mstate := migrationReader.Get(c.UserContext())
		return c.JSON(fiber.Map{
			"ok":                true,
			"service":           "instant.dev",
			"commit_id":         buildinfo.GitSHA,
			"build_time":        buildinfo.BuildTime,
			"version":           buildinfo.Version,
			"migration_version": mstate.Filename,
			"migration_count":   mstate.Count,
			"migration_status":  mstate.Status,
		})
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

	// Deploy — Phase 6 (auth required on all endpoints).
	// POST /deploy/new is gated by RequireEnvAccess(ActionDeploy) — the
	// env scope arrives as a multipart form field (not JSON or query), so
	// we provide a custom env-lookup that reads c.FormValue("env") and
	// falls back to "production" for the policy check.
	deployGroup := app.Group("/deploy", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())
	deployGroup.Post("/new",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				if v := c.FormValue("env"); v != "" {
					return v, nil
				}
				return "", nil
			}),
		),
		deployH.New,
	)
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
	middleware.SetRoleLookupDB(db)  // populate auth_team_role on every RequireAuth
	middleware.SetAPIKeyDB(db)      // enable PAT auth path in RequireAuth
	middleware.SetEnvPolicyDB(db)   // RequireEnvAccess reads teams.env_policy
	api := app.Group("/api/v1", middleware.RequireAuth(cfg), middleware.PopulateTeamRole())

	// /whoami — identity probe for agents. Returning 401 here is the canonical
	// "your token is bad"; returning anything else from this endpoint means
	// the token works. Reaching for arbitrary paths like /api/v1/team gave
	// 404 instead of 401, leading to wasted token-mint retry cycles.
	whoamiH := handlers.NewWhoamiHandler(db)
	api.Get("/whoami", whoamiH.Get)

	api.Get("/resources", resourceH.List)
	// /families and /:id/family must register BEFORE /:id so Fiber routes
	// the literal segments instead of binding them to the :id wildcard.
	api.Get("/resources/families", resourceH.ListFamilies)
	api.Get("/resources/:id/family", resourceH.Family)
	api.Get("/resources/:id", resourceH.Get)
	api.Get("/resources/:id/credentials", resourceH.GetCredentials)
	// DELETE is env-policy gated: the env scope is the env recorded on the
	// resource row itself (NOT a request param). The custom lookup reads
	// the resource by URL :id and returns its env. Lookup errors fall
	// through to the handler so a 404 / 403 surfaces with the real reason
	// instead of a confusing 403/env_policy_denied.
	api.Delete("/resources/:id",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeleteResource,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				return handlers.ResourceEnvByTokenForMiddleware(c, db)
			}),
		),
		resourceH.Delete,
	)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)
	// Slice 3 of env-aware deployments — spawn a same-type, same-family
	// twin in a new env. Tier-gated to Pro+ inside the handler. The
	// resource type the source row carries determines which low-level
	// provisioner (db/cache/nosql) runs.
	api.Post("/resources/:id/provision-twin", twinH.ProvisionTwin)

	// Team env-policy (slice 6) — owner edits, any member reads.
	// Owner-check is enforced inside Put (with a structured 403 body that
	// mirrors RequireEnvAccess's shape) rather than via RequireRole, so the
	// dashboard and agents see one consistent error keyword for env-policy
	// rejections.
	api.Get("/team/env-policy", envPolicyH.Get)
	api.Put("/team/env-policy", envPolicyH.Put)

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

	// Promo code validator — HTTP wrapper around plans.ValidatePromotion +
	// admin_promo_codes lookup. Separate handler so its (db, rdb,
	// planRegistry) deps are explicit at the constructor boundary;
	// rate-limited per-team per-hour to make brute-forcing seed codes
	// impractical. See billing_promotion.go.
	billingPromoH := handlers.NewBillingPromotionHandler(db, rdb, planRegistry)
	api.Post("/billing/promotion/validate", billingPromoH.ValidatePromotion)

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
	// PATCH edits access-control fields (private + allowed_ips) without a
	// rebuild. Pro+ tier gate enforced inside the handler; shares
	// validatePrivateDeployFields with POST /deploy/new so the rule-set is
	// audited in one place.
	api.Patch("/deployments/:id", deployH.Patch)

	// Stack management endpoints — Phase 6 (under /api/v1)
	api.Get("/stacks", stackH.List)

	// Env promotion — Pro+ "promote staging → production" + sibling envs.
	// Tier gate (pro/team/growth) is enforced inside the handler so the
	// router doesn't have to know the policy. RequireEnvAccess gates the
	// target env (read from the "to" field via the default JSON lookup).
	api.Post("/stacks/:slug/promote",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy),
		stackH.Promote,
	)

	// Env family — Pro+ "show me production + staging + dev variants of
	// this app side-by-side." Same tier gate as promote (handler-enforced).
	// Read-only; the handler emits a short Cache-Control: private, max-age=60
	// since family metadata is read-only and per-team-scoped but must NOT
	// be cached across promotes/redeploys.
	api.Get("/stacks/:slug/family", stackH.Family)

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

	// Admin / customer-management surface (Track A). Two independent gates:
	//
	//   Gate 1 — UNGUESSABLE PATH PREFIX (cfg.AdminPathPrefix). When the
	//            env var ADMIN_PATH_PREFIX is empty/unset, the admin routes
	//            are NOT registered at all. /api/v1/admin/customers returns
	//            404, drive-by scanners get no signal. When set, routes
	//            register under /api/v1/<prefix>/customers/... — the literal
	//            /api/v1/admin/customers is never a valid route.
	//
	//   Gate 2 — ADMIN_EMAILS ALLOWLIST (middleware.RequireAdmin). Reads
	//            the JWT email against ADMIN_EMAILS, closed by default —
	//            an unset/empty env var rejects every caller. See
	//            internal/middleware/admin.go for the allowlist contract.
	//
	// Either gate alone is insufficient: the path is a secret with the same
	// blast radius as a session token, and the allowlist is the second factor.
	// Defense in depth, not security-through-obscurity-alone.
	//
	// IMPORTANT: the admin endpoints are intentionally NOT documented in
	// the public OpenAPI spec (/openapi.json). See handlers/openapi.go.
	if cfg.AdminPathPrefix != "" {
		adminCustH := handlers.NewAdminCustomersHandler(db, planRegistry)
		// Wire the real Razorpay portal so admin demotes cancel the customer's
		// active subscription out-of-band (CancelImmediately — see
		// internal/razorpaybilling/portal.go for the cycle-end-vs-immediate
		// rationale). If RAZORPAY_KEY_ID isn't set in this environment the
		// portal returns "billing not configured" which the handler logs and
		// records on the audit row's cancel_succeeded=false flag — the demote
		// still succeeds.
		adminCustH.CancelSubscription = func(subID string) error {
			portal := &razorpaybilling.Portal{DB: db, Cfg: cfg}
			return portal.CancelImmediately(subID)
		}
		adminGroup := api.Group("/"+cfg.AdminPathPrefix, middleware.RequireAdmin())
		adminGroup.Get("/customers", adminCustH.List)
		adminGroup.Get("/customers/:team_id", adminCustH.Detail)
		adminGroup.Post("/customers/:team_id/tier", adminCustH.ChangeTier)
		adminGroup.Post("/customers/:team_id/promo", adminCustH.IssuePromo)

		// Promo lifecycle audit feed. /audit is uncached (admin needs to see
		// "issued at 3 sec ago"); /stats is Redis-cached 5 min (the totals tile
		// the dashboard polls). See handlers/admin_promos_audit.go for the
		// freshness contract.
		adminPromosH := handlers.NewAdminPromosAuditHandler(db, rdb)
		adminGroup.Get("/promos/audit", adminPromosH.Audit)
		adminGroup.Get("/promos/stats", adminPromosH.Stats)
	}

	// Quota-wall nudge endpoint — Track U1. Returns the most recent
	// near_quota_wall row (written by the worker's QuotaWallNudgeWorker)
	// scoped to the caller's team and bounded to the last 24h. The
	// dashboard polls this on mount + every 5 minutes to decide whether
	// to render the upgrade banner. See handlers/usage_wall.go.
	usageWallH := handlers.NewUsageWallHandler(db)
	api.Get("/usage/wall", usageWallH.GetWall)

	// A/B-experiment conversion sink — the dashboard fires
	// POST /api/v1/experiments/converted from the click handler
	// on an experimental UI element (e.g. the Upgrade button)
	// before navigating to checkout. Writes an audit_log row
	// (kind = "experiment.conversion") tagged with the variant
	// the user clicked. See internal/experiments for the
	// registry + bucket selector.
	experimentsH := handlers.NewExperimentsHandler(db)
	api.Post("/experiments/converted", experimentsH.Converted)

	// Vault — per-team encrypted secret storage (Phase 1: Heroku-shape platform).
	vaultH := handlers.NewVaultHandler(db, cfg, planRegistry)
	api.Put("/vault/:env/:key", vaultH.PutSecret)
	api.Get("/vault/:env/:key", vaultH.GetSecret)
	api.Get("/vault/:env", vaultH.ListKeys)
	api.Delete("/vault/:env/:key", vaultH.DeleteSecret)
	api.Post("/vault/:env/:key/rotate", vaultH.RotateSecret)
	// Vault env-to-env bulk copy (Pro+ tier-gated inside the handler) —
	// pairs with POST /api/v1/stacks/:slug/promote for the dashboard's
	// "promote staging → production" flow. RequireEnvAccess gates the
	// target env using the default "to" JSON-body lookup.
	api.Post("/vault/copy",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite),
		vaultH.CopySecrets,
	)

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
