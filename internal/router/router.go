package router

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/gofiber/contrib/otelfiber/v2"
	"github.com/gofiber/fiber/v2"
	fiberCORS "github.com/gofiber/fiber/v2/middleware/cors"
	fiberRecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/newrelic/go-agent/v3/newrelic"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"instant.dev/common/analyticsevent"
	"instant.dev/common/analyticsevent/nr"
	"instant.dev/common/buildinfo"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	"instant.dev/internal/migrations"
	"instant.dev/internal/plans"
	"instant.dev/internal/providers/compute/k8s"
	storageprovider "instant.dev/internal/providers/storage"
	"instant.dev/internal/provisioner"
	"instant.dev/internal/razorpaybilling"
)

// ShutdownHooks bundles handlers that participate in graceful shutdown
// (MR-P0-7). Today: Readyz.MarkDraining — flips /readyz to 503 so the
// kubelet pulls the pod from the Service endpoint list before the
// listener stops accepting connections.
type ShutdownHooks struct {
	Readyz *handlers.ReadyzHandler
}

// New creates and configures the Fiber application with all middleware and routes registered.
//
// nrApp may be nil — the New Relic Go agent fails open when no license
// key is set (local dev, CI). The NewRelic Fiber middleware degrades to
// a no-op in that case, so the rest of the chain is unaffected.
//
// Legacy entrypoint — existing tests use it. Production main.go uses
// NewWithHooks so the graceful-shutdown wiring has the ReadyzHandler.
func New(cfg *config.Config, db *sql.DB, rdb *redis.Client, geoDbs *middleware.GeoDBs, emailClient *email.Client, planRegistry *plans.Registry, provClient *provisioner.Client, nrApp *newrelic.Application) *fiber.App {
	app, _ := NewWithHooks(cfg, db, rdb, geoDbs, emailClient, planRegistry, provClient, nrApp)
	return app
}

// processStart is captured once per process so /healthz can report
// `uptime_seconds` for liveness diagnostics without an external clock.
// Sampled via time.Now() at package-load time — there is no production
// reason to mutate it after first read. Tests that want to assert a
// specific uptime override it via processStartFunc.
//
// BUG-P272 (QA 2026-05-29): `/healthz` previously did not expose
// uptime, leaving canaries / agents unable to distinguish "freshly
// rolled pod" from "pod that's been alive for hours" without a
// separate metrics scrape. The new `uptime_seconds` field plus the
// existing `build_time` give a self-contained "when did this pod
// start and how long has it been up" signal on every shallow probe.
var processStart = time.Now()

// processStartFunc is the seam that lets tests pin the uptime value.
// Production code reads processStart directly; test code can swap
// processStartFunc to a fixed instant to assert the JSON field.
var processStartFunc = func() time.Time { return processStart }

// probeOptionsHandler returns a Fiber handler that responds 204 + an
// Allow header to bare `OPTIONS /<probe>` calls. Without it Fiber's
// "no route for verb" path returns 405 — fine for browser preflight
// (the CORS middleware lower in the chain handles Origin-bearing
// requests) but surprising for curl / uptime-checker / SDK probes
// that do not set Origin. Used by the shallow probe surfaces
// (/livez, /healthz, /readyz, /openapi.json) per BUG-API-024 /
// BUG-API-025. The Allow header mirrors the verbs the routed
// handlers expose so an HTTP-conformant client sees the same allow
// set whether it reads it from a 405 envelope or a 204 OPTIONS
// response.
func probeOptionsHandler(allow string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("Allow", allow)
		return c.SendStatus(fiber.StatusNoContent)
	}
}

// NewWithHooks is the production entrypoint — returns both the Fiber
// app and the ShutdownHooks needed for graceful shutdown.
func NewWithHooks(cfg *config.Config, db *sql.DB, rdb *redis.Client, geoDbs *middleware.GeoDBs, emailClient *email.Client, planRegistry *plans.Registry, provClient *provisioner.Client, nrApp *newrelic.Application) (*fiber.App, ShutdownHooks) {
	app := fiber.New(fiber.Config{
		// Disable default error handler — we write our own JSON errors.
		// Routes that go through respondError write their own body and
		// return ErrResponseWritten; this handler is only the fallback
		// path for Fiber-generated errors (404, 405, 413 Payload Too
		// Large, etc.) that never touched a handler.
		//
		// We funnel those into handlers.respondError equivalents so the
		// envelope shape (request_id, retry_after_seconds, agent_action)
		// is identical to handler-emitted errors — agents see one shape
		// regardless of who wrote the body.
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
			case fiber.StatusRequestEntityTooLarge:
				errKey, msg = "payload_too_large", "Request payload exceeds the maximum allowed size"
			case fiber.StatusUnsupportedMediaType:
				errKey, msg = "unsupported_media_type", "Content-Type not supported for this endpoint"
			default:
				errKey, msg = "internal_error", "An unexpected error occurred"
			}
			// Delegate to handlers.WriteFiberError so the standard envelope
			// (request_id + retry_after_seconds + agent_action fallback +
			// Retry-After header on 503/429/502/504) is identical to what
			// handler-layer respondError emits. WriteFiberError returns
			// ErrResponseWritten to satisfy the same multi-return-helper
			// contract that respondError honors at the handler layer —
			// but inside the ErrorHandler itself, returning a non-nil
			// error to Fiber kicks the default 500 path. Swallow the
			// sentinel here so Fiber sees a clean nil and serves the
			// status code we already wrote.
			_ = handlers.WriteFiberError(c, code, errKey, msg)
			return nil
		},
		// Trust proxy headers for real IPs.
		//
		// T13 P1-1 (BugHunt 2026-05-20): when TRUSTED_PROXY_CIDRS is set,
		// enable EnableTrustedProxyCheck so Fiber only honours XFF from
		// inside those CIDRs (e.g. the DOKS load-balancer subnet).
		// Without this, a client could spoof XFF and poison
		// geo/ASN→fingerprint dedup or falsify audit-log source IPs.
		// Leaving it disabled keeps the legacy permissive behaviour for
		// local dev / docker-compose where the api is reached directly.
		ProxyHeader:             "X-Forwarded-For",
		EnableTrustedProxyCheck: cfg.TrustedProxyCIDRs != "",
		TrustedProxies:          parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs),
		// T13 P2-T13-05 (BugHunt 2026-05-20): set an explicit global
		// BodyLimit so a single 1 GB JSON body cannot pin a goroutine
		// across three full passes (Body+utf8.Valid+BodyParser). Fiber's
		// default is 4 MiB. We set 50 MiB — the size of the largest
		// legitimate body on any route — so the limit is uniform and
		// auditable:
		//   - /deploy/new       — multipart tarball, per-handler 50 MiB
		//   - /stacks/new       — multipart tarball, per-handler 50 MiB
		//   - /webhooks/github/* — push payloads, per-handler 25 MiB
		//   - everything else   — JSON bodies, typically sub-KB
		// The per-handler `fh.Size > 50<<20` checks in deploy.go /
		// stack.go / github_deploy.go remain authoritative for their
		// shapes; this global bounds the absolute worst case.
		// Anything bigger than 50 MiB hits the Fiber ErrorHandler above
		// which emits a JSON `payload_too_large` envelope — see T19 P1-2.
		BodyLimit: 50 * 1024 * 1024,
	})

	// ── Liveness probe (MUST be registered before any middleware) ────────────
	// GET /livez — "the process is alive." NO database check, NO migration
	// check, NO auth, NO rate-limit, NO logging context. Pure process-up
	// signal so a k8s liveness probe can distinguish "process alive" from
	// "process ready" (the deep readiness matrix lives at /readyz — see
	// handlers/readyz.go; /healthz is the shallow build-SHA + migration
	// stamp surface that canaries hit post-deploy). BUG-API-202: an
	// earlier copy of this block said "readiness signal lives at /healthz"
	// which was wrong — /healthz is the shallow probe, /readyz is the
	// per-component readiness matrix wired to the k8s readinessProbe.
	//
	// Wired here BEFORE the app.Use(...) chain so the kubelet's probe
	// traffic (~6/min/pod from livenessProbe + readinessProbe split, per
	// W5-D) never touches the rate limiter — rate-limiting your own
	// kubelet is silly. Same path will be mirrored on the
	// provisioner-sidecar (8092), worker-healthz (8091), and migrator
	// (8090) in sibling-repo PRs.
	app.Get("/livez", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"alive": true})
	})
	// BUG-API-025 (QA 2026-05-29): bare `OPTIONS /livez` (no Origin
	// header, e.g. curl/uptime-checker style probes) used to fall
	// through to Fiber's "no route" handler and return 405 because
	// the CORS middleware (which is the usual OPTIONS responder)
	// skips when Origin is unset. Browser preflight (Origin present)
	// still flows through fiberCORS below — this OPTIONS shim only
	// covers the no-Origin probe lane and returns 204 with the same
	// Allow header set Fiber would have emitted on a routed 405.
	app.Options("/livez", probeOptionsHandler("GET, HEAD, OPTIONS"))

	// ── Middleware chain (order matters) ─────────────────────────────────────
	// SecurityHeaders runs BEFORE RequestID so the static defense-in-depth
	// response headers (X-Content-Type-Options, X-Frame-Options,
	// Referrer-Policy, Permissions-Policy, Cross-Origin-Resource-Policy, and
	// — in prod only — Strict-Transport-Security) land on every response
	// including the cheap-path 404/405/livez surfaces that the request-id
	// middleware also covers AND the 4xx/5xx envelopes returned by
	// handler/middleware rejections downstream. The middleware is
	// allocation-free per request; all values are static strings. Spec
	// source: api task #311 wave-3 chaos-verify redo.
	app.Use(middleware.SecurityHeaders(cfg.Environment == "production"))
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

	// WS4 behavioral-intelligence funnel events. Build the process-wide
	// analyticsevent.Emitter ONCE here and install it for the handler funnel
	// emit sites (db/cache/nosql/vector/queue/storage/webhook provision,
	// onboarding claim, billing paid). It reuses the SAME *newrelic.Application
	// the middleware above uses — no second NR connection. ANALYTICS_BACKEND
	// defaults to "noop", so this is INERT until New Relic is configured; the
	// emitter is fail-open (the wrapper swallows any sink panic), so funnel
	// emission can never block or error a request. A nil nrApp degrades the
	// "newrelic" backend to noop inside the nr sink (nil-app drop).
	wireAnalyticsEmitter(cfg, nrApp)

	// Telemetry must come before Recover so that panic-induced 500s are recorded.
	app.Use(middleware.Telemetry())
	app.Use(fiberRecover.New(fiberRecover.Config{
		EnableStackTrace: cfg.Environment == "development",
	}))
	// P2 (BugBash 2026-05-18): the three http://localhost:* origins are
	// dev-only — shipping them in the prod allowlist lets a page served
	// from an attacker-controlled localhost dev server make credentialed
	// cross-origin calls. Append them only when ENVIRONMENT=development.
	corsAllowOrigins := "https://instanode.dev,https://www.instanode.dev"
	if cfg.Environment == "development" {
		corsAllowOrigins += ",http://localhost:5173,http://localhost:3000,http://localhost:5174"
	}
	const corsAllowMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	const corsAllowHeaders = "Content-Type,Authorization,X-Request-ID,X-E2E-Test-Token,X-E2E-Source-IP"
	// corsMaxAgeSeconds — 24h preflight cache (Firefox/Safari upper bound;
	// Chrome will clamp to 2h regardless). BUG-API-303 (QA 2026-05-29):
	// without this value the browser re-preflights every CORS request.
	const corsMaxAgeSeconds = 86400
	// BUG-API-066/067: Fiber's CORS middleware sets Access-Control-Allow-*
	// headers but does NOT validate the inbound preflight request — a
	// browser asking for TRACE or Cookie still gets a 204 even though
	// neither is in the allowlist. We pre-empt that by walking the
	// preflight headers and 403'ing any value not in our allowlist BEFORE
	// CORS responds. Same allowlist as the CORS Config below so the two
	// stay in lockstep.
	app.Use(middleware.PreflightAllowlist(corsAllowMethods, corsAllowHeaders))
	app.Use(fiberCORS.New(fiberCORS.Config{
		// Production origin (GitHub Pages serves instanode.dev). Local-dev
		// ports are appended only in development (see corsAllowOrigins above)
		// so the prod allowlist stays auditable and localhost-free.
		AllowOrigins:  corsAllowOrigins,
		AllowMethods:  corsAllowMethods,
		AllowHeaders:  corsAllowHeaders,
		ExposeHeaders: "X-Request-ID,X-Instant-Upgrade,X-Instant-Notice",
		// AUTH-004 follow-up (2026-05-30): /auth/exchange is called from the
		// dashboard SPA with `credentials: 'include'` so the browser sends
		// the HttpOnly `instanode_session_exchange` cookie cross-origin
		// (instanode.dev → api.instanode.dev). For the browser to ALLOW the
		// SPA to read the response body, the response must carry
		// `Access-Control-Allow-Credentials: true`. Without it, fetch
		// rejects the read with the generic "Failed to fetch" / "blocked
		// by CORS policy" error. Safe because AllowOrigins is an explicit
		// allowlist (no `*` — the CORS spec forbids credentials + wildcard
		// origin precisely to prevent rogue sites from siphoning cookies).
		AllowCredentials: true,
		// BUG-API-303 (QA 2026-05-29): without Access-Control-Max-Age the
		// browser re-issues an OPTIONS preflight before every CORS request.
		// 24h (corsMaxAgeSeconds) is the modern browsers' clamp ceiling —
		// Chrome caps at 2h, Firefox 24h, Safari 7d, so the practical
		// effect is per-browser but we ask for the maximum standard value
		// so cooperative agents (and reverse proxies) cache for the longest
		// period. Pairs with the Vary: Origin header already emitted to
		// keep per-origin caches safe.
		MaxAge: corsMaxAgeSeconds,
	}))
	app.Use(middleware.GeoEnrich(geoDbs))
	app.Use(middleware.Fingerprint())
	app.Use(middleware.RateLimit(rdb, middleware.RateLimitConfig{
		Limit:     100,
		KeyPrefix: "rl",
	}))

	// ── Handlers ─────────────────────────────────────────────────────────────
	// P0-1 (CIRCUIT-RETRY-AUDIT-2026-05-20): wrap the base email client in
	// a process-wide consecutive-failure circuit breaker. Every keyed
	// transactional send (payment receipt, dunning, team-invite,
	// deletion-confirm) is gated by the breaker so a Brevo brownout
	// fast-fails after N consecutive errors instead of stalling every
	// request handler on the SDK timeout. The breaker is shared across
	// all handlers via the Mailer interface (*Client and *BreakingClient
	// both satisfy it).
	breakingMailer := email.NewBreakingClient(emailClient)
	onboardH := handlers.NewOnboardingHandler(db, cfg, emailClient)
	authH := handlers.NewAuthHandler(db, cfg)
	authH.SetRedis(rdb) // P1-K: single-use OAuth state consume
	cliAuthH := handlers.NewCLIAuthHandler(db, rdb, cfg, planRegistry)
	// Build storage provider once and share it with both StorageHandler and ResourceHandler
	// so that DELETE /api/v1/resources/:id can deprovision MinIO IAM users.
	//
	// Backend selection:
	//   - OBJECT_STORE_MODE / OBJECT_STORE_BACKEND → minio-admin (default) or shared-key
	//   - storage.ResolveBackend normalises aliases ("admin", "iam" → minio-admin;
	//     "shared", "shared_key" → shared-key)
	//
	// Fail-closed rule: in ENVIRONMENT=production, shared-key mode requires
	// the explicit OBJECT_STORE_ALLOW_SHARED_KEY=true escape hatch. Without
	// it the provider stays nil, /storage/new returns 503, and the operator
	// sees a startup error in the log — preferable to silently shipping a
	// configuration where every customer holds the master access key.
	var storageProv *storageprovider.Provider
	if cfg.ObjectStoreEndpoint != "" {
		backend := storageprovider.ResolveBackend(cfg.ObjectStoreMode)
		if backend == storageprovider.BackendSharedKey && cfg.Environment == "production" && !cfg.ObjectStoreAllowSharedKey {
			slog.Error("storage: refusing to start in shared-key mode in production",
				"backend", backend,
				"environment", cfg.Environment,
				"hint", "set OBJECT_STORE_MODE=admin (with admin creds) or OBJECT_STORE_ALLOW_SHARED_KEY=true to override")
		} else if sp, err := storageprovider.NewWithBackend(
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
			slog.Info("storage: provider initialized",
				"backend", backend,
				"endpoint", cfg.ObjectStoreEndpoint,
				"bucket", cfg.ObjectStoreBucket,
				"isolation", isolationLabel(backend),
			)
			storageProv = sp
		}
	}

	resourceH := handlers.NewResourceHandler(db, rdb, cfg, planRegistry, provClient, storageProv)
	teamMembersH := handlers.NewTeamMembersHandler(db, cfg, planRegistry, breakingMailer, rdb)
	envPolicyH := handlers.NewEnvPolicyHandler(db)
	dbH := handlers.NewDBHandler(db, rdb, cfg, provClient, planRegistry)
	vectorH := handlers.NewVectorHandler(db, rdb, cfg, provClient, planRegistry)
	cacheH := handlers.NewCacheHandler(db, rdb, cfg, provClient, planRegistry)
	nosqlH := handlers.NewNoSQLHandler(db, rdb, cfg, provClient, planRegistry)
	// twinH composes the three above so POST /api/v1/resources/:id/provision-twin
	// dispatches to the same low-level provision pipelines as /db/new etc.
	// Wire AFTER the three constructors so the handler instances exist.
	twinH := handlers.NewTwinHandler(dbH, cacheH, nosqlH)
	// bulkTwinH — POST /api/v1/families/bulk-twin. Wires the same three
	// per-type handlers as twinH so the bulk path reuses the same
	// provision pipelines (no fork). See family_bulk_twin.go.
	bulkTwinH := handlers.NewBulkTwinHandler(db, dbH, cacheH, nosqlH, planRegistry)
	queueH := handlers.NewQueueHandler(db, rdb, cfg, provClient, planRegistry)
	storageH := handlers.NewStorageHandler(db, rdb, cfg, storageProv, planRegistry)
	webhookH := handlers.NewWebhookHandler(db, rdb, cfg, planRegistry)
	logsH := handlers.NewLogsHandler(db)
	deployH := handlers.NewDeployHandler(db, rdb, cfg, planRegistry)
	stackH := handlers.NewStackHandler(db, rdb, cfg, planRegistry)
	// Wire the shared email client for the two-step deletion flow
	// (Wave FIX-I). Constructed separately so existing tests that
	// instantiate the handlers directly can opt out of the email path
	// without touching the constructor signature. emailClient may be
	// nil on a misconfigured boot — the handlers detect that and fall
	// back to immediate destruction.
	deployH.SetEmailClient(breakingMailer)
	stackH.SetEmailClient(breakingMailer)

	// P3: start the background teardown reconciler. The worker's
	// DeploymentExpirer only flips expired deploys to status='expired' —
	// the api owns the compute provider and is the only service that can
	// actually destroy the namespace / pod / Ingress / cert. Without this
	// sweep every auto-expired deployment leaked live, billed infra
	// forever. context.Background() is intentional: the sweep should run
	// for the whole process lifetime (the api has no graceful-shutdown
	// context to thread through here).
	deployH.StartTeardownReconciler(context.Background())

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

	// Public discovery handlers — instantiated early so they can wire under
	// `app` (no /api/v1 group, no auth) below.
	capabilitiesH := handlers.NewCapabilitiesHandler(planRegistry)
	incidentsH := handlers.NewIncidentsHandler()
	statusH := handlers.NewStatusHandler(db, rdb)

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
		// BUG-API-090 / BUG-API-217 (QA 2026-05-29): /healthz is a
		// public probe (no auth, no rate-limit by token). Emitting the
		// raw migration filename leaked the table/feature names embedded
		// in it ("063_forwarder_sent_audit_link.sql" tells an attacker a
		// forwarder_sent→audit_log FK landed at migration 63). Strip to
		// the numeric prefix only via State.PublicVersion so canaries
		// keep their commit_id+count+version tuple but no domain
		// knowledge leaks. migration_count + migration_status unchanged.
		// BUG-API-417 (QA 2026-05-29): include the server's current wall
		// clock in /healthz so canaries / SDKs / agents can detect clock
		// skew between their host and the api pod without an extra round
		// trip. RFC 3339 with millisecond precision matches the format
		// used in audit-log and forwarder_sent rows; `now` is sourced
		// from time.Now().UTC() so the value is unambiguous regardless
		// of the pod's local TZ. build_time is the immutable image stamp;
		// `now` is the live read — keeping both lets a probe compute the
		// pod's uptime as a sanity check too.
		// BUG-API-146/148/309 (QA 2026-05-29): the `service` field used to
		// emit "instant.dev" — the legacy brand name. Now emits "instanode-api"
		// so /healthz aligns with the runtime brand (instanode.dev) and the
		// log-line serviceName ("api" / "instant-api"). Canaries that key on
		// `service` to disambiguate api vs worker vs provisioner /healthz
		// stamps benefit from the new value too — see handlers/readyz.go
		// where worker/provisioner probes report "instanode-worker" and
		// "instanode-provisioner" in sibling repos.
		// BUG-P272 (QA 2026-05-29): expose `uptime_seconds` (int64) so
		// canaries / agents can answer "how long has this pod been up?"
		// without a separate metrics scrape. Computed from processStartFunc()
		// (a test-overridable seam) and rounded to seconds — sub-second
		// jitter has no diagnostic value at this surface and would defeat
		// HTTP-cache deduplication if anyone proxies the response.
		uptimeSeconds := int64(time.Since(processStartFunc()).Seconds())
		// BUG-API-300 (QA 2026-05-29): /healthz is the canonical surface
		// the rule-14 build-SHA gate reads after every deploy. Without a
		// Cache-Control hint, any intermediary (Cloudflare edge, browser
		// fetch cache, kubectl-port-forward'd browser tab, NR synthetic
		// monitor) may return a stale commit_id read for seconds-to-minutes
		// after a rollout — silently breaking the "did the new image
		// actually land" verification. Stamp `no-store` so probes always
		// hit the live pod. Cost: a few hundred bytes of header per probe;
		// upside: zero stale build-SHA reads, matching the contract canaries
		// already assume. Pairs with the OPTIONS shim above.
		c.Set(fiber.HeaderCacheControl, "no-store")
		return c.JSON(fiber.Map{
			"ok":                true,
			"service":           "instanode-api",
			"commit_id":         buildinfo.GitSHA,
			"build_time":        buildinfo.BuildTime,
			"version":           buildinfo.Version,
			"migration_version": mstate.PublicVersion(),
			"migration_count":   mstate.Count,
			"migration_status":  mstate.Status,
			"now":               time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
			"uptime_seconds":    uptimeSeconds,
		})
	})
	// BUG-API-025 (QA 2026-05-29): mirror the /livez OPTIONS shim on
	// /healthz so curl/uptime-checker style probes that send a bare
	// `OPTIONS /healthz` (no Origin) get a 204 instead of the 405 Fiber
	// returns when no route matches the verb. Browser CORS preflight
	// (Origin present) still flows through fiberCORS below.
	app.Options("/healthz", probeOptionsHandler("GET, HEAD, OPTIONS"))

	// /readyz — deep, component-by-component readiness probe wired to
	// the k8s readinessProbe (NOT livenessProbe — see /healthz above
	// which stays the shallow liveness check). The handler runs all
	// component checks in parallel with a 10s per-check cache so probe
	// traffic doesn't hammer upstreams. See handlers/readyz.go for the
	// check registry, criticality rules, and the Brevo silent-rejection
	// motivation (RETRO 2026-05-20).
	readyzH := handlers.NewReadyzHandler(cfg, db, rdb, provClient)
	app.Get("/readyz", readyzH.Get)
	// BUG-API-025 (QA 2026-05-29): same OPTIONS shim as /healthz/livez.
	app.Options("/readyz", probeOptionsHandler("GET, HEAD, OPTIONS"))

	// OpenAPI spec — machine-readable description of the agent-facing API.
	// T19 P0-1 (BugHunt 2026-05-20): pass ENVIRONMENT so the served spec
	// strips /internal/set-tier in production (where the route is not
	// registered — see line 1019 — and leaking it in the doc lies to
	// agents + advertises an internal privilege-escalation surface).
	handlers.SetOpenAPIEnvironment(cfg.Environment)
	// T10 P1-4 (BugHunt 2026-05-20): drop http://localhost from the
	// return_to allowlist in production. A victim on a machine where
	// an attacker controls a localhost listener could otherwise have
	// the session_token redirected there.
	handlers.SetReturnToAllowsLocalhost(cfg.Environment != "production")
	app.Get("/openapi.json", handlers.ServeOpenAPI)
	// BUG-API-024 (QA 2026-05-29): bare `OPTIONS /openapi.json` (no
	// Origin header — e.g. an SDK doing a preflight probe before a
	// custom-header GET) used to return 405 because no route matched
	// the verb. The CORS middleware below only responds when Origin
	// is set. Register an explicit OPTIONS handler so the no-Origin
	// probe lane returns 204 + the Allow header set the browser CORS
	// preflight would otherwise see via fiberCORS.
	app.Options("/openapi.json", probeOptionsHandler("GET, HEAD, OPTIONS"))

	// /llms.txt — agent discovery doc, 302 to marketing where it's the
	// source of truth. Agents that hit api.instanode.dev first land here
	// and follow the redirect to instanode.dev/llms.txt (and its companion
	// /llms-full.txt) without a 404 dead-end. P1 persona finding 2026-05-14.
	app.Get("/llms.txt", func(c *fiber.Ctx) error {
		return c.Redirect("https://instanode.dev/llms.txt", fiber.StatusFound)
	})
	app.Get("/llms-full.txt", func(c *fiber.Ctx) error {
		return c.Redirect("https://instanode.dev/llms-full.txt", fiber.StatusFound)
	})

	// Public capability + incident discovery for AI agents — no auth.
	// /capabilities answers "what can I do at which tier?" without
	// provisioning-to-discover-limits. /incidents returns [] today and
	// reserves the response shape for the future incident-feed worker.
	app.Get("/api/v1/capabilities", capabilitiesH.Get)
	app.Get("/api/v1/incidents", incidentsH.List)
	// Public real-backend status: replaces the dashboard's client-side
	// probe loop with a server-side aggregate driven by the worker's
	// `uptime_prober` job. Cached 60s in Redis. No auth — anyone can ask
	// "is instanode up". See handlers/status.go.
	app.Get("/api/v1/status", statusH.Get)

	// MCP authorization profile — RFC 8414 / OAuth 2.0 Protected Resource Metadata.
	app.Get("/.well-known/oauth-protected-resource", handlers.ServeOAuthProtectedResourceMetadata)

	// BUG-API-411 (QA 2026-05-29): RFC 9116 — security researchers reach for
	// /.well-known/security.txt to find a responsible-disclosure contact
	// before filing a public vulnerability report. Pre-fix both api and
	// apex returned 404 for both /.well-known/security.txt and /security.txt
	// which made the disclosure surface effectively unreachable. We serve
	// the same body from BOTH paths so a researcher's first guess works
	// regardless of which convention they hit, and the body validates
	// cleanly against https://securitytxt.org/ — Contact + Expires + the
	// Preferred-Languages and Canonical fields the standard recommends.
	//
	// Expires is set 1 year from the build_time stamp so the file stays
	// fresh as long as the binary is redeployed regularly (each new
	// image pushes the window forward). When the binary stalls past its
	// expiry the file silently becomes stale-but-still-served — that's
	// the right call vs returning 410, which would lock out researchers
	// during a deploy freeze.
	serveSecurityTxt := makeSecurityTxtHandler(time.Now())
	app.Get("/.well-known/security.txt", serveSecurityTxt)
	// Some scanners + older guidance hit /security.txt at the root. RFC
	// 9116 §3 names the .well-known path as canonical (the file itself
	// declares it via the Canonical: field above) but the apex path is
	// a documented fallback — serving the same body avoids a needless
	// 404 on the legacy path.
	app.Get("/security.txt", serveSecurityTxt)

	// Prometheus metrics — gated by METRICS_TOKEN when set (open in local dev).
	app.Get("/metrics", func(c *fiber.Ctx) error {
		if cfg.MetricsToken != "" {
			auth := c.Get("Authorization")
			// P2 (BugBash 2026-05-18): constant-time compare — a plain `!=`
			// on the secret leaks its length and prefix via response timing.
			expected := "Bearer " + cfg.MetricsToken
			if subtle.ConstantTimeCompare([]byte(auth), []byte(expected)) != 1 {
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

	// Email-link approval workflow for non-dev env promotions (migration 026).
	// Public, token-IS-the-credential route — never sits inside the /api/v1
	// RequireAuth group. Rate-limited per-IP inside the handler (defends the
	// token space against brute-force).
	promoteApprovalH := handlers.NewPromoteApprovalHandler(db, rdb)
	app.Get("/approve/:token", promoteApprovalH.Approve)

	// Provisioning — Phase 2+ (gated by IsServiceEnabled in each handler)
	// OptionalAuth is registered per-route rather than via app.Group("/", ...) to avoid
	// accidentally applying it globally to all routes (Fiber's "/" group prefix matches everything).
	//
	// RequireWritable runs AFTER OptionalAuth on every mutating provisioning
	// endpoint so an impersonated (read-only) session presenting an
	// Authorization header is 403'd before the handler runs. Anonymous (no
	// header) callers fall through — OptionalAuth never sets the read_only
	// local, and RequireWritable is a no-op for unset locals. The same
	// invariant covers /webhook/receive/:token: that route never reads
	// Authorization headers in practice, but installing the gate keeps
	// the policy uniform — see test #5 in PR #024 for the explicit
	// "POST /db/new under an impersonated session must 403" assertion.
	// Idempotency middleware (per-endpoint, AFTER OptionalAuth + RequireWritable
	// so the scope can read auth_team_id when present, falling back to the
	// fingerprint set by the global Fingerprint() middleware). Rate-limit
	// runs at app.Use scope above, so replays still consume rate budget —
	// this is the intentional anti-abuse posture documented in
	// internal/middleware/idempotency.go. See that file for the full
	// rationale on the rate-budget vs quota-budget split.
	// T19 P1-7 (BugHunt 2026-05-20): provisioning routes use the strict
	// OptionalAuth variant — a present-but-invalid Authorization header
	// returns 401 instead of silently falling through to anonymous-tier
	// provisioning. This closes the "agent with expired token gets
	// anonymous limits with no signal" bug. Missing headers still pass
	// through as anonymous (the routes are explicitly anonymous-capable).
	app.Post("/db/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "db.new"), dbH.NewDB)
	app.Post("/vector/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "vector.new"), vectorH.NewVector)
	app.Post("/cache/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "cache.new"), cacheH.NewCache)
	app.Post("/nosql/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "nosql.new"), nosqlH.NewNoSQL)
	app.Post("/queue/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "queue.new"), queueH.NewQueue)
	app.Post("/storage/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "storage.new"), storageH.NewStorage)
	// POST /storage/:token/presign — broker-mode access path. Authentication is
	// the token in the URL (the same token returned by /storage/new). Used by
	// agents on DO Spaces today where no long-lived credential is issued.
	// Middleware chain (B17-P0, 2026-05-20):
	//   - OptionalAuth — non-strict: a session JWT is OPTIONAL. When
	//     present, the handler cross-checks the JWT's team_id against
	//     the resource's team_id (a leaked token + a legit but
	//     different-team session must not be able to impersonate the
	//     resource owner). Bad/expired JWTs silently drop to anonymous
	//     here — strict mode would 401 every anonymous broker access
	//     loop, which is the common case.
	//   - PresignTokenRateLimit — per-:token sliding window
	//     (10/min/token). Complements the global per-IP RateLimit at
	//     app.Use scope: a leaked token used from a botnet of distinct
	//     IPs is throttled by THIS counter even when the per-IP limiter
	//     sees only one hit per source. See
	//     internal/middleware/presign_token_rate_limit.go for the
	//     algorithm.
	//   - Idempotency — Stripe-shape Idempotency-Key + body-fingerprint
	//     fallback, matching every other mutating endpoint. Without
	//     this, an agent's retry of a transient 5xx mints two presigned
	//     URLs from the same logical request, each consuming a slot in
	//     the per-token rate limit.
	// H46 F1 (2026-05-21): OptionalAuthStrict (not bare OptionalAuth) so
	// a malformed/expired JWT 401s instead of silently falling through
	// to anonymous. The token in the URL remains the primary auth
	// boundary for the anonymous case; strict mode ensures a caller who
	// *thinks* they're authenticated but presents a stale session
	// doesn't sign for an unowned tenant prefix.
	//
	// 2026-05-30: the H46 F1 fix landed in the comment but not in the
	// chain (the route was still using bare OptionalAuth) — caught by
	// the registry-iterating regression test in
	// optional_auth_strict_coverage_test.go. Now matches the comment.
	app.Post("/storage/:token/presign",
		middleware.OptionalAuthStrict(cfg),
		middleware.PresignTokenRateLimit(rdb),
		middleware.Idempotency(rdb, "storage.presign"),
		storageH.PresignStorage,
	)
	app.Post("/webhook/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "webhook.new"), webhookH.NewWebhook)
	// /webhook/receive/:token is registered with app.All so any HTTP method
	// (GET for Slack URL verification, POST for the bulk of webhook senders,
	// PUT/DELETE for a handful of esoteric flows) reaches the handler
	// instead of bouncing off a 405. Auth is the token in the URL — no
	// session middleware applies (BugBash #Q29).
	app.All("/webhook/receive/:token", webhookH.Receive)
	app.Get("/resources/:token/logs", logsH.ResourceLogs)

	// GitHub auto-deploy receiver (migration 035) — PUBLIC, signed.
	// GitHub itself POSTs here on every push. Auth = HMAC-SHA256
	// verification against the per-connection secret (X-Hub-Signature-256
	// header). NOT placed under any RequireAuth middleware because GitHub
	// presents no session token; signature is the boundary.
	githubReceiveH := handlers.NewGitHubDeployHandler(db, cfg, planRegistry)
	app.Post("/webhooks/github/:webhook_id", githubReceiveH.Receive)

	// GitHub App install flow (P4.1), gated by cfg.GitHubAppEnabled. Install
	// requires auth (binds the install to the team); Callback is state-
	// authenticated (GitHub presents no session, only the signed state).
	githubAppH := handlers.NewGitHubAppHandler(db, cfg, planRegistry)
	app.Get("/integrations/github/install", middleware.RequireAuth(cfg), githubAppH.Install)
	app.Get("/integrations/github/callback", githubAppH.Callback)

	// App-level GitHub webhook (P4.2) — one endpoint for ALL installations,
	// signed with the App webhook secret. No auth/RequireAuth: the HMAC is the
	// boundary (mirrors the manual receiver above).
	githubAppWebhookH := handlers.NewGitHubAppWebhookHandler(db, rdb, cfg, planRegistry)
	app.Post("/webhooks/github", githubAppWebhookH.Receive)

	// Deploy — Phase 6 (auth required on all endpoints).
	// POST /deploy/new is gated by RequireEnvAccess(ActionDeploy) — the
	// env scope arrives as a multipart form field (not JSON or query), so
	// we provide a custom env-lookup that reads c.FormValue("env") and
	// falls back to "production" for the policy check.
	// RequireWritable on the deploy group rejects impersonated sessions
	// before any mutating deploy handler runs. GETs (deployGroup.Get) are
	// no-ops under the middleware so the impersonated admin can still
	// inspect deploy state — which is the entire point of view-as-customer.
	// RequireDPoP is opt-in per token: bearers without `cnf.jkt` pass through
	// unchanged (back-compat for dashboard/CLI sessions), but agent-issued
	// key-bound tokens MUST present a fresh DPoP proof on every mutating
	// /deploy/* call. A stolen bearer alone can't be replayed without the
	// matching private key. See internal/middleware/dpop.go for the chain.
	deployGroup := app.Group("/deploy",
		middleware.RequireAuth(cfg),
		middleware.PopulateTeamRole(),
		middleware.RequireDPoP(rdb),
		middleware.RequireWritable(),
	)
	deployGroup.Post("/new",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				if v := c.FormValue("env"); v != "" {
					return v, nil
				}
				return "", nil
			}),
		),
		// Idempotency runs AFTER env-policy so a rejected env doesn't get
		// cached as a 4xx and replay on a future approved env. (Same key,
		// same body, but the policy state may differ — replaying the cached
		// 403 would be wrong. The downside is a tiny window where two
		// concurrent POSTs with the same key both pass policy and race the
		// cache write; the per-request 5xx-not-cached rule and the
		// per-fingerprint rate-limit cap the blast radius.)
		middleware.Idempotency(rdb, "deploy.new"),
		deployH.New,
	)
	deployGroup.Get("/:id", deployH.Get)
	deployGroup.Get("/:id/logs", deployH.Logs)
	deployGroup.Patch("/:id/env", deployH.UpdateEnv)
	deployGroup.Delete("/:id", deployH.Delete)
	deployGroup.Post("/:id/redeploy", deployH.Redeploy)
	// Scale-to-zero explicit wake (Task #54). Gated by
	// DEPLOY_SCALE_TO_ZERO_ENABLED inside the handler → 501 when off.
	deployGroup.Post("/:id/wake", deployH.Wake)

	// Stacks — Phase 6 multi-service.
	// New/Get/Logs/Delete are anonymous-capable (same model as /db/new etc.).
	// UpdateEnv/Redeploy require auth (mutations on owned stacks).
	// RequireWritable rejects impersonated sessions on all mutating
	// stack endpoints (POST/PATCH/DELETE) so an admin viewing the
	// customer's stack page can't accidentally redeploy / nuke it.
	// Idempotency middleware on /stacks/new + /stacks/:slug/redeploy
	// covers accidental double-clicks / agent retries the same way it
	// does for /deploy/new (multipart-aware fingerprint) and /db/new etc.
	//
	// MUTATING routes (POST/DELETE) use OptionalAuthStrict for the same
	// reason as /db/new etc. (T19 P1-7, 2026-05-20): a present-but-bad
	// bearer header returns 401 instead of silently downgrading the
	// caller to anonymous-tier provisioning. /stacks/new + DELETE
	// /stacks/:slug were missed in the original strict-mode wave — this
	// closes the surface (rule 17 / MR-P1-38 follow-up). A missing
	// Authorization header still passes through as anonymous, since the
	// routes are explicitly anonymous-capable.
	//
	// READ routes (GET) intentionally stay non-strict: a logged-out tab
	// reading /stacks/:slug (e.g. follow-up after revocation) should not
	// 401 the page — it should serve the anonymous read view if the slug
	// belongs to an anonymous stack, or 404 otherwise.
	app.Post("/stacks/new", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "stacks.new"), stackH.New)
	app.Get("/stacks/:slug", middleware.OptionalAuth(cfg), stackH.Get)
	app.Get("/stacks/:slug/logs/:svc", middleware.OptionalAuth(cfg), stackH.Logs)
	app.Delete("/stacks/:slug", middleware.OptionalAuthStrict(cfg), middleware.RequireWritable(), stackH.Delete)
	app.Patch("/stacks/:slug/env", middleware.RequireAuth(cfg), middleware.RequireWritable(), stackH.UpdateEnv)
	app.Post("/stacks/:slug/redeploy", middleware.RequireAuth(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "stacks.redeploy"), stackH.Redeploy)

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
	//
	// The email client is wrapped in a circuit breaker that opens after 5
	// consecutive send failures and stays open for 30s. When open,
	// SendMagicLink returns errCircuitOpen without invoking the inner client,
	// which the Start handler treats as any other send failure (warn log,
	// status='send_failed' persisted, 202 to the caller). NR-facing
	// counters (email.circuit.attempts/failures/opens) live on the
	// handlers package and are surfaced through GetMagicLinkCircuitMetrics.
	mlMailer := handlers.NewCircuitBreakingMagicLinkMailer(emailClient)
	// A04 (P1): pass Redis so the handler can enforce per-email rate limits.
	// NewMagicLinkHandlerWithMailerAndRedis falls back to fail-open when rdb
	// is nil, so this is safe even in environments where Redis is unavailable.
	mlH := handlers.NewMagicLinkHandlerWithMailerAndRedis(db, cfg, mlMailer, authH, rdb)
	app.Post("/auth/email/start", mlH.Start)
	app.Get("/auth/email/callback", mlH.Callback)
	// Wave FIX-I — email-link 302 to the dashboard's confirm-deletion
	// page. The API does NOT process the token here (a click is
	// navigation, not action); the dashboard's authenticated POST is
	// the real confirm step.
	app.Get("/auth/email/confirm-deletion", handlers.EmailConfirmDeletionRedirectHandler(cfg.DashboardBaseURL))

	// CLI device-flow login — POST creates session, GET polls for completion.
	// POST /auth/cli/:id/complete (D2) is the missing call site that flips a
	// pending session to complete: the dashboard makes an AUTHENTICATED POST
	// (user's session Bearer) once the user approves the login, which mints the
	// team API key + claimed tokens and writes the completed Redis state so the
	// CLI's poll returns the api_token. RequireAuth gates it — only a signed-in
	// user can complete their own login.
	app.Post("/auth/cli", cliAuthH.CreateCLISession)
	app.Post("/auth/cli/:id/complete", middleware.RequireAuth(cfg), cliAuthH.CompleteCLISessionHandler)
	app.Get("/auth/cli/:id", cliAuthH.PollCLISession)
	app.Get("/auth/me", middleware.RequireAuth(cfg), cliAuthH.GetCurrentUser)

	// AUTH-004: browser-only bridge between the magic-link / OAuth callback
	// and the SPA. The callback sets a 30-second, Path=/auth/exchange cookie
	// (instanode_session_exchange) carrying the session JWT and redirects
	// with ?signed_in=1. The SPA POSTs /auth/exchange with credentials, the
	// handler reads the cookie, clears it (Max-Age=0), and returns the JWT
	// in the body. RequireAuth deliberately does NOT honour the cookie —
	// every subsequent API call is Bearer-only, preserving the contract
	// every CLI/MCP/SDK consumer already implements.
	app.Post("/auth/exchange", authH.Exchange)

	// A03 (P1): server-side session invalidation. POST /auth/logout stores the
	// JWT's jti in Redis so subsequent requests with the same token are rejected
	// by RequireAuth. RequireAuth checks the revocation set via IsJTIRevoked.
	// SetRevocationDB wires the Redis client into the middleware package once
	// so every RequireAuth call can query it without threading rdb through
	// every handler constructor.
	//
	// BUG-AUTH-005: per the OpenAPI contract, POST /auth/logout is
	// idempotent — "safe to call without a valid token." We therefore do
	// NOT gate it on RequireAuth; the handler itself returns 200 {ok:true}
	// for missing/malformed/expired credentials (the local token is already
	// useless, so the dashboard's logout-on-expiry hitting this surface
	// must not 401). Tokens that DO parse cleanly are revoked normally.
	middleware.SetRevocationDB(rdb)
	logoutH := handlers.NewLogoutHandler(cfg, rdb)
	app.Post("/auth/logout", logoutH.Logout)

	// Billing
	billing := handlers.NewBillingHandler(db, cfg, breakingMailer)
	// Legacy alias kept for backward compatibility; canonical path is
	// /api/v1/billing/checkout (registered under the /api/v1 group below).
	// RequireWritable rejects impersonated sessions — an admin viewing-as-
	// customer must not be able to start a checkout on the customer's
	// behalf. The canonical /api/v1 alias is already gated by the api
	// group's RequireWritable.
	//
	// Idempotency middleware: dedup accidental double-submits (cross-tab
	// clicks, mobile double-taps) before they reach Razorpay. The handler
	// MAY ALSO have a per-team Redis SETNX guard (FOLLOWUP-2 / BB2-D5);
	// the two protections stack — SETNX runs inside the handler AFTER
	// this middleware, so a fingerprint-cache hit short-circuits before
	// SETNX is ever attempted.
	app.Post("/billing/checkout", middleware.RequireAuth(cfg), middleware.RequireWritable(), middleware.Idempotency(rdb, "billing.checkout"), billing.CreateCheckoutAPI)
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	// Internal machine-to-machine terminate endpoint. Called by the
	// worker's payment_grace_terminator dispatcher after a team's
	// 7-day Razorpay-failure grace expires. Authenticated by a
	// shared HS256 secret (WORKER_INTERNAL_JWT_SECRET) that MUST be
	// distinct from JWT_SECRET — see config.go for the rationale.
	// Lives next to /razorpay/webhook because both are non-session
	// external triggers, NOT under /api/v1 (no team-scoped auth
	// applies). The handler enforces fail-closed behavior when the
	// secret is unset: every call 401s until the operator wires the
	// k8s Secret in both the api and worker workloads.
	internalTermPortal := &razorpaybilling.Portal{DB: db, Cfg: cfg}
	internalTerminateH := handlers.NewInternalTerminateHandler(db, cfg, internalTermPortal.CancelAtCycleEnd)
	app.Post("/internal/teams/:id/terminate", internalTerminateH.Terminate)

	// Internal worker-driven resend for magic_links that failed their first
	// send attempt. The worker's magic_link_reconciler periodic job (every
	// 60s) sweeps rows stuck at email_send_status IN ('pending', 'send_failed')
	// inside the 15-minute TTL window and POSTs the row id here.
	// Same fail-closed posture as /internal/teams/:id/terminate: when
	// WORKER_INTERNAL_JWT_SECRET is unset, every call 401s.
	//
	// Reuses mlMailer (the circuit-wrapped mailer) so the breaker sees
	// every email attempt — primary sends AND worker-driven resends. If
	// the provider is degraded, the breaker opens on whichever path hits
	// it first, and both paths immediately fast-fail.
	internalResendH := handlers.NewInternalResendMagicLinkHandler(db, cfg, mlMailer)
	app.Post("/internal/email/resend-magic-link", internalResendH.Resend)

	// FIX-H (#65/#Q47) — credit the per-team manual-backup daily counter
	// when the worker observes a manual backup failing terminally. Same
	// fail-closed auth posture as the other /internal/* routes.
	internalRefundH := handlers.NewInternalBackupRefundHandler(db, rdb, cfg)
	app.Post("/internal/teams/:id/backup-quota/refund", internalRefundH.Refund)

	// CI-only ephemeral-test-account surface. Registered UNCONDITIONALLY
	// (not behind the development-env gate) because CI mints+reaps real
	// test-cohort accounts against PRODUCTION. It is safe to register in
	// prod because it is INERT BY DEFAULT: both routes return 404 for every
	// request until E2E_ACCOUNT_TOKEN is set, and even when set they require
	// a constant-time X-E2E-Token header match (404 on mismatch — the route's
	// existence is hidden). The reap path can NEVER delete a real team
	// (403 not_test_cohort on any non-is_test_cohort team). Lives next to the
	// other /internal/* machine-to-machine routes — NOT under /api/v1 (no
	// customer session auth applies) and NOT in the public OpenAPI spec
	// (deliberately omitted; see handlers/openapi.go header). See
	// handlers/internal_e2e_account.go for the full guard rationale.
	e2eAccountH := handlers.NewE2EAccountHandler(db, rdb, cfg)
	app.Post("/internal/e2e/account", e2eAccountH.CreateAccount)
	app.Delete("/internal/e2e/account/:team_id", e2eAccountH.ReapAccount)

	// §10.20 cached-aggregation endpoints. Separate handlers from BillingHandler
	// so the caching contract (Redis + singleflight + Cache-Control headers)
	// is visible at the route + handler boundary, not buried inside the billing
	// state aggregator. Wired below under the /api/v1 group.
	billingUsageH := handlers.NewBillingUsageHandler(db, rdb, planRegistry)
	teamSummaryH := handlers.NewTeamSummaryHandler(db, rdb, planRegistry)
	teamSelfH := handlers.NewTeamSelfHandler(db, planRegistry)

	// Public webhook request listing — token IS the credential (no session needed).
	// Authenticated callers use the same handler; it additionally verifies team ownership.
	app.Get("/api/v1/webhooks/:token/requests", middleware.OptionalAuth(cfg), webhookH.ListRequests)

	// Public token-based invitation accept — must be registered BEFORE the
	// /api/v1 auth group so the group middleware doesn't catch it.
	// (Token IS the auth here — no Bearer required.)
	teamsHPublic := handlers.NewTeamsHandler(db, cfg, breakingMailer)
	app.Post("/api/v1/invitations/:token/accept", teamsHPublic.AcceptInvitation)

	// Email-provider feedback webhooks — bounces, unsubscribes, spam
	// complaints. Each handler authenticates the inbound call via
	// HMAC (Brevo) or SNS-TopicArn match (SES), so they MUST register
	// before the /api/v1 auth group — the group's RequireAuth would
	// otherwise demand a Bearer token from Brevo's servers.
	//
	// PII: the raw payload is persisted to email_events.raw for audit,
	// but the handlers DO NOT log it. See email_webhooks.go.
	emailWebhookH := handlers.NewEmailWebhookHandler(db, cfg)
	app.Post("/api/v1/email/webhook/brevo", emailWebhookH.Brevo)
	app.Post("/api/v1/email/webhook/ses", emailWebhookH.SES)
	// API-98 (QA 2026-05-29): explicit 405 + Allow: POST on the GET verb so
	// a provider dashboard pre-flight that GETs the configured webhook URL
	// sees "endpoint exists, method wrong" rather than the catch-all 404 /
	// 401 envelope (which some dashboards interpret as "URL invalid" and
	// silently drop). Registered BEFORE the /api/v1 RequireAuth group so the
	// group middleware doesn't catch the GET and 401 it.
	app.Get("/api/v1/email/webhook/brevo", emailWebhookH.BrevoMethodNotAllowed)
	app.Get("/api/v1/email/webhook/ses", emailWebhookH.SESMethodNotAllowed)

	// Brevo transactional-delivery receiver — closes the "201 ≠ delivered"
	// gap. Brevo's transactional API returns 201 on accept but actual
	// SMTP-relay happens async. This endpoint receives per-event callbacks
	// (delivered/soft_bounce/hard_bounce/blocked/complaint/deferred/
	// unsubscribed/error) and updates forwarder_sent.classification +
	// delivered_at to reflect the ACTUAL outcome, not the API-acceptance
	// state.
	//
	// Auth shape: URL-token (BREVO_WEBHOOK_SECRET in the :secret path
	// segment), NOT HMAC. Brevo's transactional webhooks don't carry
	// HMAC signatures by default; the URL-token approach works without
	// requiring per-callback signing toggles in the dashboard. See
	// brevo_webhook.go for the full rationale.
	//
	// Registered BEFORE the /api/v1 auth group (same reason as the
	// HMAC-signed /api/v1/email/webhook/brevo above): Brevo's servers
	// present no Authorization header.
	brevoTxH := handlers.NewBrevoTransactionalWebhookHandler(db, cfg)
	app.Post("/webhooks/brevo/:secret", brevoTxH.Receive)

	// Authenticated resource management
	middleware.SetRoleLookupDB(db) // populate auth_team_role on every RequireAuth
	middleware.SetAPIKeyDB(db)     // enable PAT auth path in RequireAuth
	middleware.SetEnvPolicyDB(db)  // RequireEnvAccess reads teams.env_policy
	// RequireWritable gates every mutating route under /api/v1/* against
	// the read_only JWT flag minted by the admin-impersonation endpoint
	// (POST /api/v1/admin/customers/:team_id/impersonate). GET/HEAD/OPTIONS
	// fall through unconditionally — the impersonated admin's whole reason
	// for holding the token is to *read* the customer's dashboard state.
	//
	// One deliberate exemption: the impersonation-mint endpoint itself
	// (registered below inside the admin group). It is called by an admin
	// holding a *normal* (writable) session, so the gate would never fire
	// there — but the brief calls out the exemption explicitly, and the
	// audit-comment in router.go is where reviewers expect to find it.
	//
	// RequireDPoP is opt-in per bearer token: only requests whose JWT carries
	// `cnf.jkt` are gated by the proof check. Dashboard/CLI sessions that
	// don't bind to a key pass through unchanged. This is what makes wiring
	// the middleware here back-compat safe — every existing dashboard, MCP,
	// and CLI client keeps working — while sender-bound agent tokens get
	// the full RFC 9449 enforcement chain (signature, jkt match, htm/htu,
	// iat freshness, jti replay). See internal/middleware/dpop.go.
	api := app.Group("/api/v1",
		middleware.RequireAuth(cfg),
		middleware.PopulateTeamRole(),
		middleware.RequireDPoP(rdb),
		middleware.RequireWritable(),
	)

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
	// W7F — per-resource observability. Tier-gated to Pro+ inside the
	// handler (anonymous/free → 402); hobby/pro/growth/team are bounded by
	// per-tier window caps. Returns synthetic samples + data_source:"stub"
	// until W5-A's prober.go starts writing real probe rows.
	api.Get("/resources/:id/metrics", resourceH.Metrics)
	// DELETE is env-policy gated: the env scope is the env recorded on the
	// resource row itself (NOT a request param). The custom lookup reads
	// the resource by URL :id and returns its env. Lookup errors fall
	// through to the handler so a 404 / 403 surfaces with the real reason
	// instead of a confusing 403/env_policy_denied.
	api.Delete("/resources/:id",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeleteResource,
			middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
				return handlers.ResourceEnvByTokenOrIDForMiddleware(c, db)
			}),
		),
		resourceH.Delete,
	)
	api.Post("/resources/:id/rotate-credentials", resourceH.RotateCredentials)
	// Pause / Resume — Pro+ "suspend without deletion." Tier gate is
	// enforced inside the handler so the 402 response shape matches the
	// other multi-env walls. POST not PATCH because the side-effects (REVOKE
	// CONNECT, ACL off, revokeRolesFromUser) are not idempotent at the
	// provider level even though the DB flip is — POST signals "command,
	// not state replacement."
	api.Post("/resources/:id/pause", resourceH.Pause)
	api.Post("/resources/:id/resume", resourceH.Resume)
	// Slice 3 of env-aware deployments — spawn a same-type, same-family
	// twin in a new env. Tier-gated to Pro+ inside the handler. The
	// resource type the source row carries determines which low-level
	// provisioner (db/cache/nosql) runs. Idempotency middleware covers
	// accidental double-creates of the twin resource (one of the most
	// expensive accidental side-effects on the platform).
	api.Post("/resources/:id/provision-twin", middleware.Idempotency(rdb, "resources.provision-twin"), twinH.ProvisionTwin)
	// Bulk env-twinning — one call to twin every "parent" resource in
	// source_env into target_env. Same Pro+ tier gate. Returns 200 on
	// full success, 207 Multi-Status when any individual twin fails so
	// the caller can keep the successful rows and retry just the
	// failures. See handlers/family_bulk_twin.go for the contract.
	api.Post("/families/bulk-twin", middleware.Idempotency(rdb, "families.bulk-twin"), bulkTwinH.BulkTwin)

	// Customer backups + restore (migration 031). Tier-gating + per-day
	// rate-limit live inside the handler; the api group's RequireAuth +
	// RequireWritable already cover unauthenticated and impersonated
	// callers. The worker (sibling repo) picks up pending rows from
	// resource_backups / resource_restores within 30s and owns every
	// state transition past 'pending'.
	backupH := handlers.NewBackupHandler(db, rdb, planRegistry)
	// Idempotency middleware on the two POST routes — a double-tap on the
	// dashboard's "Back up now" or "Restore" button would otherwise spawn
	// two pending rows for the worker to process. The 120s fingerprint
	// window matches the typical pre-handoff click latency.
	api.Post("/resources/:id/backup", middleware.Idempotency(rdb, "resources.backup"), backupH.CreateBackup)
	api.Get("/resources/:id/backups", backupH.ListBackups)
	api.Post("/resources/:id/restore", middleware.Idempotency(rdb, "resources.restore"), backupH.CreateRestore)
	api.Get("/resources/:id/restores", backupH.ListRestores)

	// Team env-policy (slice 6) — owner edits, any member reads.
	// Owner-check is enforced inside Put (with a structured 403 body that
	// mirrors RequireEnvAccess's shape) rather than via RequireRole, so the
	// dashboard and agents see one consistent error keyword for env-policy
	// rejections.
	api.Get("/team/env-policy", envPolicyH.Get)
	api.Put("/team/env-policy", envPolicyH.Put)

	api.Get("/team/members", teamMembersH.ListMembers)
	// Idempotency middleware: protects against double-clicks on the
	// "Invite member" form. Without it, a flaky network + retry sends
	// two invitation emails and creates two pending invitation rows
	// (each consuming a separate invitation token).
	api.Post("/team/members/invite", middleware.Idempotency(rdb, "team.members.invite"), teamMembersH.InviteMember)
	api.Post("/team/members/leave", teamMembersH.LeaveTeam)
	api.Delete("/team/members/:user_id", teamMembersH.RemoveMember)
	// PATCH /team/members/:user_id — owner-only role update (admin / developer
	// / viewer / member). Owner role is NOT assignable via PATCH; use
	// POST .../promote-to-primary for an atomic ownership transfer.
	api.Patch("/team/members/:user_id", teamMembersH.UpdateRole)
	// POST /team/members/:user_id/promote-to-primary — owner-only atomic
	// transfer of the team's primary anchor + owner role.
	api.Post("/team/members/:user_id/promote-to-primary", teamMembersH.PromoteToPrimary)
	api.Get("/team/invitations", teamMembersH.ListInvitations)
	api.Delete("/team/invitations/:id", teamMembersH.RevokeInvitation)
	api.Post("/team/invitations/:id/accept", teamMembersH.AcceptInvitation)

	// GDPR Article 17 — right-to-be-forgotten. Owner-only (RequireRole gates
	// at the route boundary). The handler additionally enforces a
	// confirm_team_slug body match before any state change. See
	// handlers/team_deletion.go for the full lifecycle contract; the
	// post-grace destruction happens in the worker's team_deletion_executor
	// (see worker/internal/jobs/team_deletion_executor.go).
	teamDelH := handlers.NewTeamDeletionHandler(db, cfg)
	teamDelH.CancelSubscription = &handlers.PortalSubscriptionCanceler{DB: db, Cfg: cfg}
	api.Delete("/team", middleware.RequireRole("owner"), teamDelH.Delete)
	api.Post("/team/restore", middleware.RequireRole("owner"), teamDelH.Restore)

	api.Get("/billing", billing.GetBillingState)
	// Canonical billing checkout. Idempotency middleware: see the legacy
	// /billing/checkout alias above for the rationale and the FOLLOWUP-2
	// SETNX stacking note.
	api.Post("/billing/checkout", middleware.Idempotency(rdb, "billing.checkout"), billing.CreateCheckoutAPI)
	// Self-serve POST /billing/cancel was removed per policy — see project
	// memory project_no_self_serve_cancel_downgrade.md. Cancellation flows
	// through Razorpay's own dashboard, executed by support staff, which
	// fires subscription.cancelled → handleSubscriptionCancelled in the
	// webhook handler (still wired below at /razorpay/webhook).
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

	// GET / PATCH /api/v1/team — wired so the dashboard's TeamPage "Rename
	// team" stops being a visual lie (previously the api had no PATCH
	// endpoint; the dashboard's updateTeam() returned the input unchanged).
	// D05 (P1): PATCH requires owner role — only the team owner may rename the
	// team. RequireRole("owner") is installed at the route layer so the
	// handler itself need not repeat the check, and audit consumers can
	// distinguish a forbidden rename from a forbidden resource deletion.
	api.Get("/team", teamSelfH.Get)
	api.Patch("/team", middleware.RequireRole(middleware.RoleOwner), middleware.RequireWritable(), teamSelfH.Update)

	// Deploy management endpoints — Phase 6 (aliases under /api/v1)
	api.Get("/deployments", deployH.List)
	api.Get("/deployments/:id", deployH.Get)
	// GET /deployments/:id/events — failure-timeline read surface (swarm
	// triggering incident 2026-05-30: silent-deploy-failure bug class). Same
	// RBAC as GET /deployments/:id; returns the deployment_events rows the
	// worker's deploy_failure_autopsy job writes, ordered DESC by created_at.
	// Read-only — events are written by the worker, never by the api.
	api.Get("/deployments/:id/events", deployH.Events)
	api.Delete("/deployments/:id", deployH.Delete)
	// Wave FIX-I — two-step email-confirmed deletion. POST confirms
	// (validates ?token=<plaintext> against the hashed pending row),
	// DELETE cancels (the dashboard's "I changed my mind" path). Both
	// inherit RequireAuth + RequireWritable from the /api/v1 group —
	// anonymous deploys never enter this flow.
	api.Post("/deployments/:id/confirm-deletion", deployH.ConfirmDelete)
	api.Delete("/deployments/:id/confirm-deletion", deployH.CancelDelete)
	// PATCH edits access-control fields (private + allowed_ips) without a
	// rebuild. Pro+ tier gate enforced inside the handler; shares
	// validatePrivateDeployFields with POST /deploy/new so the rule-set is
	// audited in one place.
	api.Patch("/deployments/:id", deployH.Patch)
	// Deploy TTL keepers (Wave FIX-J — migration 045). make-permanent flips
	// expires_at to NULL; /ttl sets a custom expires_at = now()+hours.
	// Both mutate state, so RequireWritable to reject impersonated sessions.
	// Anonymous tier is rejected inside the handler with the
	// "claim the account" agent_action.
	api.Post("/deployments/:id/make-permanent", middleware.RequireWritable(), deployH.MakePermanent)
	api.Post("/deployments/:id/ttl", middleware.RequireWritable(), deployH.SetTTL)

	// Team settings — Wave FIX-J. GET is open to any team member; PATCH
	// requires admin role (owner or admin) because flipping the default
	// affects every future /deploy/new on the team.
	teamSettingsH := handlers.NewTeamSettingsHandler(db)
	api.Get("/team/settings", teamSettingsH.Get)
	api.Patch("/team/settings",
		middleware.RequireWritable(),
		middleware.RequireRole(middleware.RoleAdmin),
		teamSettingsH.Update,
	)

	// GitHub auto-deploy (migration 035). Customers wire a deployment to
	// a GitHub repo; pushes to the tracked branch trigger a fresh deploy.
	// All three /api/v1 routes are auth-required (inherited from the
	// `api` group middleware) and Pro+ tier-gated inside the handler.
	// The public receive endpoint is registered separately below — it
	// must NOT inherit RequireAuth because GitHub itself does not present
	// a session token; signature verification is the auth boundary.
	githubDeployH := handlers.NewGitHubDeployHandler(db, cfg, planRegistry)
	api.Post("/deployments/:id/github", middleware.RequireWritable(), githubDeployH.Connect)
	api.Get("/deployments/:id/github", githubDeployH.Get)
	api.Delete("/deployments/:id/github", middleware.RequireWritable(), githubDeployH.Disconnect)

	// Stack management endpoints — Phase 6 (under /api/v1)
	api.Get("/stacks", stackH.List)
	// GET /api/v1/stacks/:slug — per-stack status polling for StackCreatePage.
	// The Get handler uses optionalStackTeam internally; under the /api/v1 group
	// auth is already enforced by RequireAuth so any authenticated team member
	// can poll their own stack's status. D09/C06 fix: this route was absent,
	// causing every fetchStackStatus() call to 404 and the build page to time out.
	api.Get("/stacks/:slug", stackH.Get)
	// Wave FIX-I — stack-side two-step deletion. Same contract as the
	// deploy-side endpoints; the shared resolver lives in
	// handlers/deletion_confirm.go.
	api.Post("/stacks/:slug/confirm-deletion", stackH.ConfirmDelete)
	api.Delete("/stacks/:slug/confirm-deletion", stackH.CancelDelete)

	// Env promotion — Pro+ "promote staging → production" + sibling envs.
	// Tier gate (pro/team/growth) is enforced inside the handler so the
	// router doesn't have to know the policy. RequireEnvAccess gates the
	// target env (read from the "to" field via the default JSON lookup).
	//
	// Idempotency middleware: the dev-env promote path executes
	// immediately (creating a new stack row) and the non-dev path
	// creates a pending_approval row + sends an email. Both are
	// vulnerable to double-clicks. The migration-026 approval gate
	// dedups EXECUTION but not the CREATION of the pending_approval
	// row, so the middleware is additive — see project memory
	// project_no_self_serve_cancel_downgrade.md for the related
	// philosophy on idempotent-by-construction vs. middleware-guarded.
	api.Post("/stacks/:slug/promote",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionDeploy),
		middleware.Idempotency(rdb, "stacks.promote"),
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
	// Idempotency middleware: a double-click on "Create API key" would
	// otherwise mint two long-lived tokens; the plaintext is only shown
	// to the user once, so the second token is also instantly orphaned.
	apiKeysH := handlers.NewAPIKeysHandler(db)
	api.Post("/auth/api-keys", middleware.Idempotency(rdb, "auth.api-keys.create"), apiKeysH.Create)
	api.Get("/auth/api-keys", apiKeysH.List)
	api.Delete("/auth/api-keys/:id", apiKeysH.Revoke)

	// Per-team audit log — customer-facing export.
	//
	//   GET /api/v1/audit       → JSON, cursor-paginated, tier-gated.
	//   GET /api/v1/audit.csv   → text/csv, streamed (for piping into
	//                              a customer's own SIEM).
	//
	// Tier gate: anonymous/free → 402; hobby = 30d, pro = 90d,
	// growth/team = unlimited lookback. admin.* rows are never returned
	// regardless of tier — those are reserved for the operator audit
	// feed at /api/v1/<admin-prefix>/customers. See handlers/audit.go.
	auditH := handlers.NewAuditHandler(db)
	api.Get("/audit", auditH.List)
	api.Get("/audit.csv", auditH.ListCSV)

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
		adminNotesH := handlers.NewAdminCustomerNotesHandler(db)
		adminImpersonateH := handlers.NewAdminImpersonateHandler(db, cfg)

		// Defense-in-depth gates 3-5: AdminRateLimit → AdminAuditEmit → RequireAdmin.
		// Audit MUST sit BEFORE RequireAdmin so brute-force probes still get logged
		// on rejection (RequireAdmin returns 403 without c.Next). RateLimit first so
		// invalid-JWT spam can't bypass the limiter. See PR #58 for full rationale.
		adminGroup := api.Group("/"+cfg.AdminPathPrefix,
			middleware.AdminRateLimit(rdb),
			middleware.AdminAuditEmit(db, cfg.AdminPathPrefix),
			middleware.RequireAdmin(),
		)
		adminGroup.Get("/customers", adminCustH.List)
		adminGroup.Get("/customers/:team_id", adminCustH.Detail)
		adminGroup.Post("/customers/:team_id/tier", adminCustH.ChangeTier)
		// Idempotency middleware on promo issuance: an admin double-clicking
		// "issue $50 credit" must not result in two admin_promo_codes rows.
		// The handler has no other dedup mechanism — the body carries a
		// (kind, value, valid_for_days) tuple that's not unique-keyed in
		// the DB.
		adminGroup.Post("/customers/:team_id/promo", middleware.Idempotency(rdb, "admin.promo.issue"), adminCustH.IssuePromo)

		// Notes — free-text per-team admin annotations.
		adminGroup.Get("/customers/:team_id/notes", adminNotesH.ListNotes)
		adminGroup.Post("/customers/:team_id/notes", adminNotesH.CreateNote)
		adminGroup.Delete("/notes/:note_id", adminNotesH.DeleteNote)

		// Impersonation — mint a 10-minute read-only JWT for the target team.
		// RequireWritable on the /api/v1 group gates mutations on the read_only claim.
		adminGroup.Post("/customers/:team_id/impersonate", adminImpersonateH.Impersonate)

		// Promo lifecycle audit feed (PR #59). /audit uncached; /stats Redis-cached 5 min.
		adminPromosH := handlers.NewAdminPromosAuditHandler(db, rdb)
		adminGroup.Get("/promos/audit", adminPromosH.Audit)
		adminGroup.Get("/promos/stats", adminPromosH.Stats)

		// Deploy-identity append-only log (PR #57). Answers "which binary at $TIME?"
		deploysAuditH := handlers.NewDeploysAuditHandler(db)
		adminGroup.Get("/deploys", deploysAuditH.List)

		// Promote-approval admin surface (migration 026). Read-only list
		// + a reject endpoint that flips a pending row to rejected. The
		// public GET /approve/:token route is wired ABOVE outside the
		// admin gate — clicking the email link does NOT require an
		// admin session (the token IS the credential there).
		adminGroup.Get("/promotions", promoteApprovalH.List)
		adminGroup.Post("/promotions/:id/reject", promoteApprovalH.Reject)
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
	//
	// T11 P1-1 (BugHunt 2026-05-20): every per-key MUTATING vault route is
	// gated by RequireEnvAccess(VaultWrite) with the :env path param as the
	// lookup. Before this fix, only /vault/copy honoured the team's
	// env_policy — PUT/POST-rotate/DELETE on /vault/:env/:key bypassed the
	// policy entirely, so a `developer` could write/rotate/delete prod
	// secrets even when the team had set `{"production":{"vault_write":["owner"]}}`.
	// Reads (GET /vault/:env/:key and GET /vault/:env) stay unguarded — read
	// access is the documented default and is gated separately by the
	// in-handler tier check.
	vaultEnvLookup := middleware.WithEnvLookup(func(c *fiber.Ctx) (string, error) {
		return c.Params("env"), nil
	})
	vaultH := handlers.NewVaultHandler(db, cfg, planRegistry)
	api.Put("/vault/:env/:key",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		vaultH.PutSecret,
	)
	api.Get("/vault/:env/:key", vaultH.GetSecret)
	api.Get("/vault/:env", vaultH.ListKeys)
	api.Delete("/vault/:env/:key",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		vaultH.DeleteSecret,
	)
	// Idempotency middleware (FOLLOWUP-6, 2026-05-14): rotate creates a NEW
	// versioned row in vault_secrets on every call — double-clicking the
	// "Rotate" button in the dashboard produced two new versions
	// (BB2-CHROME-3). The middleware dedups via explicit Idempotency-Key
	// (24h TTL) or body-fingerprint fallback (120s TTL). PUT /vault/:env/:key
	// also writes a new row but is state-replacement by contract (caller
	// supplies the value, retries of the same value are functionally
	// idempotent at the read-path). DELETE is idempotent-by-construction.
	// /vault/copy is a bulk variant — flagged separately, out of scope for
	// this PR.
	api.Post("/vault/:env/:key/rotate",
		middleware.RequireEnvAccess(middleware.EnvPolicyActionVaultWrite, vaultEnvLookup),
		middleware.Idempotency(rdb, "vault.rotate"),
		vaultH.RotateSecret,
	)
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
	// Idempotency middleware: CreateInvitation parallels the older
	// /team/members/invite route — both mint a single-use token + send
	// an email, and both should resist double-clicks.
	teamsH := teamsHPublic // reuse the same handler instance
	api.Post("/teams/:team_id/invitations", middleware.RequireRole("admin"), middleware.Idempotency(rdb, "teams.invitations.create"), teamsH.CreateInvitation)
	api.Get("/teams/:team_id/invitations", middleware.RequireRole("admin"), teamsH.ListInvitations)
	api.Delete("/teams/:team_id/invitations/:id", middleware.RequireRole("admin"), teamsH.RevokeInvitation)

	// Internal dev-only endpoints — only registered in development environment.
	// These bypass Razorpay and directly mutate DB state. Never expose in production.
	if cfg.Environment == "development" {
		internal := app.Group("/internal")
		internal.Post("/set-tier", handlers.NewSetTierHandler(db))
	}

	return app, ShutdownHooks{Readyz: readyzH}
}

// isolationLabel maps the storage backend to a human-readable isolation
// posture for the startup log. Used so on-call SREs can grep one line
// to confirm prod is running per-tenant IAM users — not the shared-key
// loophole that previously gave every customer the master access key.
func isolationLabel(b storageprovider.Backend) string {
	switch b {
	case storageprovider.BackendMinIOAdmin:
		return "per-tenant-iam-user"
	case storageprovider.BackendSharedKey:
		return "shared-master-key"
	default:
		return string(b)
	}
}

// parseTrustedProxyCIDRs splits the comma-separated TRUSTED_PROXY_CIDRS env
// var into individual CIDR strings for Fiber's TrustedProxies allowlist.
// Trims whitespace, drops empty entries, and returns nil when the input is
// empty — Fiber's EnableTrustedProxyCheck handles a nil TrustedProxies list
// by skipping the check entirely. T13 P1-1 (BugHunt 2026-05-20).
func parseTrustedProxyCIDRs(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// wireAnalyticsEmitter builds the process-wide behavioral-intelligence emitter
// from ANALYTICS_BACKEND and installs it for the handler funnel emit sites via
// handlers.SetAnalyticsEmitter. It reuses the api's existing
// *newrelic.Application (the one the NewRelic middleware uses) for the
// "newrelic" backend so there is no second NR connection.
//
// Selection (all fail-open — Factory always returns a usable emitter):
//   - ANALYTICS_BACKEND=newrelic  -> the nr sink over nrApp (nrApp may be nil:
//     the sink then drops every event and fires the failure hook with nil_app).
//   - anything else / unset       -> noop (the inert default).
//
// A non-nil advisory error from Factory is logged (analytics degraded to noop)
// but never blocks boot — analytics is best-effort. Returns the installed
// emitter (the boot caller ignores it; tests drive it to exercise the wiring).
func wireAnalyticsEmitter(cfg *config.Config, nrApp *newrelic.Application) analyticsevent.Emitter {
	acfg := analyticsevent.Config{Backend: cfg.AnalyticsBackend}

	// For the New Relic backend we inject the already-constructed app via
	// Config.Override so the root analyticsevent package never imports the NR
	// agent. The failure hook bridges a dropped emit to the api's Prometheus
	// counter (CLAUDE.md rule 25: a metric needs its alert/dashboard; the
	// catalog row + Prom rule ship in this PR).
	if analyticsevent.NormalizeBackend(cfg.AnalyticsBackend) == analyticsevent.BackendNewRelic {
		acfg.Override = nr.New(nrApp, nr.WithFailureHook(func(reason string) {
			metrics.AnalyticsEmitFailed.WithLabelValues(reason).Inc()
		}))
	}

	emitter, err := analyticsevent.Factory(acfg)
	if err != nil {
		slog.Warn("analytics: degraded to noop", "backend", cfg.AnalyticsBackend, "error", err)
	}
	slog.Info("analytics: emitter wired", "backend", emitter.Name())
	handlers.SetAnalyticsEmitter(emitter)
	return emitter
}
