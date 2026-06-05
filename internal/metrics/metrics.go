package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// ProvisionsTotal counts resources provisioned, labeled by service and tier.
	ProvisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_provisions_total",
		Help: "Total resources provisioned successfully",
	}, []string{"service", "tier"})

	// ProvisionFailures counts provision failures by service and error reason.
	// error_reason values: grpc_error, db_error, quota_exceeded, soft_delete_failed
	ProvisionFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_provision_failures_total",
		Help: "Provision failures by service and error reason",
	}, []string{"service", "error_reason"})

	// ProvisionDuration observes end-to-end provision latency in seconds,
	// including the gRPC or local backend call.
	// Buckets tuned for provisioning operations (expected range: 100ms–5s).
	ProvisionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "instant_provision_duration_seconds",
		Help:    "End-to-end provision latency in seconds",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0},
	}, []string{"service", "tier"})

	// HTTPRequestDuration observes HTTP request latency per route and status class.
	// status_class is "2xx", "4xx", or "5xx" to avoid high cardinality on raw codes.
	// route is the Fiber route template (e.g., "/cache/new"), not the raw URL.
	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "instant_http_request_duration_seconds",
		Help:    "HTTP request latency by method, route, and status class",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0},
	}, []string{"method", "route", "status_class"})

	// HTTPErrors counts HTTP error responses (4xx and 5xx) for fast alerting.
	// Kept separate from HTTPRequestDuration so alert queries are simpler.
	HTTPErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_http_errors_total",
		Help: "HTTP 4xx and 5xx responses by method, route, and status class",
	}, []string{"method", "route", "status_class"})

	// GRPCDuration observes gRPC call latency to the provisioner, labeled by method.
	GRPCDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "instant_grpc_duration_seconds",
		Help:    "gRPC call latency to the provisioner service",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0},
	}, []string{"method", "status"})

	// FingerprintAbuseBlocked counts requests blocked by fingerprint rate limiting.
	FingerprintAbuseBlocked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "instant_fingerprint_abuse_blocked_total",
		Help: "Requests blocked by fingerprint rate limiting",
	})

	// IdempotencyReplayRefunded counts the rate-limit counter refunds the
	// Idempotency middleware issues on a cache HIT — one increment per
	// replayed response that successfully DECR'd the per-fingerprint
	// daily counter (CLAUDE.md FINDING API-1, fix Option C).
	//
	// Labelled by route_path so on-call can see which endpoints absorb the
	// most retry-storm traffic. A steady non-zero rate is healthy (agents
	// are retrying transient 5xx and we're honoring the published Stripe-
	// shape replay contract). A sudden spike on one route correlates with
	// upstream brownouts; flip to NR and check the corresponding 5xx rate
	// for the same route.
	//
	// Companion alert (infra repo): "idempotency replay refund spike (1h)"
	// fires when rate(idempotency_replay_refunded_total[1h]) > 5×7d
	// baseline — points the operator at a brownout in the underlying
	// provisioner before agents start abandoning.
	IdempotencyReplayRefunded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_idempotency_replay_refunded_total",
		Help: "Rate-limit counter refunds issued by Idempotency middleware on cache hit",
	}, []string{"route"})

	// RecycleGateBlocked counts anonymous provision attempts blocked by the
	// free-tier recycle gate (Option B from FREE-TIER-RECYCLE-2026-05-12).
	// Labelled by resource_type so we can see which services see the most
	// recycle attempts.
	RecycleGateBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_recycle_gate_blocked_total",
		Help: "Anonymous provisions blocked by free-tier recycle email gate",
	}, []string{"resource_type"})

	// ConversionFunnel counts conversion funnel steps:
	// provision, jwt_issued, landing_viewed, claimed, paid.
	ConversionFunnel = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_conversion_funnel_total",
		Help: "Conversion funnel steps",
	}, []string{"step"})

	// TierUpgradeTTLPromote counts invocations of the deployment-TTL
	// promote path triggered by a paid-tier upgrade
	// (PromoteDeploymentTTLsForTeam in api/internal/models/deployment.go,
	// called from billing.go handleSubscriptionCharged for tiers
	// hobby/hobby_plus/pro/growth/team).
	//
	// Labels:
	//   outcome — "success"  : the promote tx committed AND at least one
	//                          of {deploys promoted, team default flipped}
	//                          actually changed.
	//             "noop"     : the promote tx committed but nothing
	//                          changed (team had no auto_24h deploys AND
	//                          the team default was already non-auto_24h).
	//                          Healthy state — e.g. a second upgrade for a
	//                          team whose state is already promoted.
	//             "error"    : the promote tx errored — the upgrade itself
	//                          still committed (fail-open) but the per-deploy
	//                          TTL state may still carry auto_24h until the
	//                          operator runs the backfill script. NR alert
	//                          pages at outcome="error" > 0 over 10m.
	//
	// A sustained zero rate of "success" on a deploy that's seeing
	// `subscription.upgraded` audit emits would indicate the promote call
	// itself isn't wired in — the regression guard is the registry test
	// TestPromoteHookFiresOnEveryPaidTierUpgrade.
	TierUpgradeTTLPromote = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_tier_upgrade_ttl_promote_total",
		Help: "Paid-tier upgrade deployment-TTL promote outcomes (see PromoteDeploymentTTLsForTeam)",
	}, []string{"outcome"})

	// RedisErrors counts Redis operation errors by operation name.
	RedisErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_redis_errors_total",
		Help: "Redis operation errors",
	}, []string{"operation"})

	// FailOpenEvents counts every time a documented fail-open path
	// actually trips (P2 CIRCUIT-RETRY-AUDIT-2026-05-20). The api's
	// rate-limit, fingerprint, JWT-revocation, GeoIP, and email
	// suppression paths all degrade open on a downstream error — which
	// is the right call (better than silently blocking legitimate
	// requests during a Redis/Postgres blip), but ALSO a silent
	// reliability tell: a steady non-zero rate() means a downstream is
	// flapping and the rate-limit/abuse signal is effectively off.
	//
	// One counter, two labels:
	//   subsystem  — "redis_rate_limit" | "redis_fingerprint" |
	//                "redis_revocation" | "redis_quota" |
	//                "geoip" | "email_suppression" | "email_ledger_probe"
	//   reason     — short failure class label ("redis_unavailable",
	//                "db_error", "mmdb_missing", ...) — bounded
	//                cardinality, suitable for prometheus labels.
	//
	// Drives the "fail-open rate" NR alert.
	FailOpenEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_fail_open_events_total",
		Help: "Documented fail-open paths that actually tripped during a downstream error",
	}, []string{"subsystem", "reason"})

	// GeoIPDBAge reports the age of the MaxMind GeoLite2 database in hours.
	GeoIPDBAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "instant_geoip_db_age_hours",
		Help: "Age of MaxMind GeoLite2 database in hours",
	})

	// StorageIAMUsersCreated counts successful per-tenant MinIO IAM user
	// creations on /storage/new. Drives the storage_iam_users gauge (via
	// rate() in NR) and the "shared-key fallback" alert: if this counter
	// stops moving while /storage/new traffic keeps increasing, something
	// silently fell back to shared-key mode and on-call should investigate.
	StorageIAMUsersCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "instant_storage_iam_users_created_total",
		Help: "Per-tenant MinIO IAM users minted on /storage/new (admin mode)",
	})

	// StorageIAMUsersDeleted counts successful per-tenant MinIO IAM user
	// deletions on DELETE /api/v1/resources/:id and worker-driven expiry.
	StorageIAMUsersDeleted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "instant_storage_iam_users_deleted_total",
		Help: "Per-tenant MinIO IAM users removed at resource deprovision (admin mode)",
	})

	// StorageIAMUsersFailed counts IAM-user lifecycle failures. The
	// `op` label is "create" or "delete"; the `phase` label narrows
	// "create" failures to "add_user" / "add_policy" / "set_policy" so
	// on-call can tell whether MinIO admin is rejecting the user, the
	// policy doc, or the binding.
	StorageIAMUsersFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_storage_iam_users_failed_total",
		Help: "Per-tenant MinIO IAM user create/delete failures",
	}, []string{"op", "phase"})

	// DedicatedTierUpgradeBlocked counts requests rejected because the team's
	// tier is not dedicated-eligible (i.e., not growth+). Labelled by
	// handler ("db", "cache", "nosql", "queue", "vector") and team_tier.
	// A rise here means free/hobby/pro customers are trying dedicated infra.
	DedicatedTierUpgradeBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_dedicated_tier_upgrade_blocked_total",
		Help: "Requests rejected because team tier is not dedicated-eligible (growth+)",
	}, []string{"handler", "team_tier"})

	// StackProvisionLimitBlocked counts stack provision attempts rejected by the
	// per-tier deployments_apps cap from plans.yaml.
	StackProvisionLimitBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_stack_provision_limit_blocked_total",
		Help: "Stack provision attempts rejected by per-tier deployments_apps cap",
	}, []string{"team_tier"})

	// QueueProvisionLimitBlocked counts queue provision attempts rejected by the
	// per-tier queue_count cap from plans.yaml.
	QueueProvisionLimitBlocked = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_queue_provision_limit_blocked_total",
		Help: "Queue provision attempts rejected by per-tier queue_count cap",
	}, []string{"team_tier"})

	// DeployTeardownMarkFailed counts teardown-reconciler sweeps where the
	// compute was destroyed but MarkDeploymentTornDown failed to flip the
	// row to 'deleted'. The row is then retried forever — a persistently
	// non-zero rate() means a deployment is stuck and on-call must
	// investigate (DB connectivity / constraint rejection).
	DeployTeardownMarkFailed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "instant_deploy_teardown_mark_failed_total",
		Help: "Teardown sweeps where compute was destroyed but the row could not be marked 'deleted'",
	})

	// DeployEventsQueryTotal counts inbound GET /api/v1/deployments/:id/events
	// calls, labelled by `result` so on-call can split a real query rate from
	// the 404 / 400 noise floor. Used by both agents (debugging a failed
	// deploy) and the dashboard's FailureTimeline panel.
	//
	// result values (closed set, bounded cardinality):
	//   "ok"        — 200, events returned (count may be 0)
	//   "not_found" — 404, deployment id doesn't exist OR belongs to another team
	//   "invalid"   — 400, malformed id / bad query param
	//   "error"     — 5xx, DB lookup failed
	//
	// Companion alert (infra repo follow-up):
	//   "deploy events query error rate" — fires when
	//   rate(instant_deploy_events_query_total{result="error"}[10m]) /
	//   rate(instant_deploy_events_query_total[10m]) > 5%. Per rule 25 the
	//   alert JSON ships with the metric — tracked as a TODO in the PR body
	//   because the infra repo is a separate review surface.
	DeployEventsQueryTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_deploy_events_query_total",
		Help: "GET /api/v1/deployments/:id/events calls by result (ok|not_found|invalid|error)",
	}, []string{"result"})

	// DeployRedeployInPlaceTotal counts the POST /deploy/new in-place
	// redeploy outcomes (redeploy=true form field). Labels:
	//
	//   outcome = "success"          — match found, redeploy compute path invoked
	//             "not_found"        — no live deployment for (team, env, name)
	//             "wrong_team"       — name exists on a different team (404 is
	//                                  still returned — we never confirm existence)
	//             "not_redeployable" — row was reaped (expired/deleted) in the
	//                                  TOCTOU window between lookup and the
	//                                  guarded 'building' CAS → 409 (#14)
	//
	// Closes the agent-UX gap surfaced 2026-05-30 (duplicate-URL incident):
	// agents previously called /deploy/new repeatedly, minting a fresh
	// app_id per call. A rising `outcome="not_found"` rate means agents
	// are guessing names — pair with the MCP `list_deployments` tool to
	// teach them the discovery path. `outcome="success"` is the healthy
	// state — the platform served an in-place update instead of fanning
	// out a new URL.
	DeployRedeployInPlaceTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_deploy_redeploy_total",
		Help: "POST /deploy/new redeploy=true outcomes (success/not_found/wrong_team). Closes the duplicate-URL agent-UX gap (2026-05-30).",
	}, []string{"outcome"})

	// NatsAuthFailures counts NATS credential-issuance failures from the
	// common/queueprovider abstraction. MR-P0-5 (NATS per-tenant isolation,
	// 2026-05-20). A non-zero rate is almost always one of:
	//   - the operator seed in the nats-operator Secret is out of sync with
	//     the running nats-server's operator JWT (rotate one without the
	//     other and you get this);
	//   - the resolver push subject is unreachable from the api pod (network
	//     policy / SYS account creds wrong);
	//   - the embedded jwt/v2 lib failed to sign for an unexpected reason.
	// Alert at rate > 0 for 5 min — every failure means a tenant landed on
	// the legacy_open path instead of getting real isolation.
	NatsAuthFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "nats_auth_failures_total",
		Help: "NATS credential issuance failures (operator seed mismatch, resolver unreachable, signing error)",
	})

	// GoroutinePanics counts panics recovered inside fire-and-forget
	// goroutines by the safego helper. Any non-zero value means a background
	// task crashed but the pod survived — alert on rate() > 0. The `task`
	// label is the caller-supplied name of the goroutine (e.g. "runDeploy").
	GoroutinePanics = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_goroutine_panics_total",
		Help: "Panics recovered in fire-and-forget goroutines by the safego helper",
	}, []string{"task"})

	// BrevoWebhookEventsTotal counts inbound Brevo transactional-webhook
	// events at /webhooks/brevo/:secret, labelled by the normalized event
	// type written to forwarder_sent.classification. The brief's
	// "201 ≠ delivered" gap closes once this counter sees real traffic:
	//   - rate(brevo_webhook_events_total{event="delivered"}[5m]) /
	//     rate(brevo_webhook_events_total[5m]) gives the live
	//     delivery ratio. Alert on < 95% over 1h.
	//   - sum by (event) gives the per-class breakdown (bounced_hard,
	//     bounced_soft, rejected, complaint, deferred, unsubscribed,
	//     error, unhandled, missing_message_id, unauthorized,
	//     invalid_payload, oversized).
	//
	// Cardinality is bounded: the labels are a closed set defined in
	// brevo_webhook.go (the LedgerClass* constants + the admin labels
	// "unauthorized" / "invalid_payload" / "oversized" / "unhandled" /
	// "missing_message_id" / "error"). No user-controlled values land
	// here.
	BrevoWebhookEventsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "brevo_webhook_events_total",
		Help: "Inbound Brevo transactional-webhook events by normalized class (delivered/bounced_hard/bounced_soft/rejected/complaint/deferred/unsubscribed/error/unhandled/missing_message_id/unauthorized/invalid_payload/oversized)",
	}, []string{"event"})

	// GitHubWebhookReceivedTotal counts inbound GitHub App webhook deliveries to
	// POST /webhooks/github by event type and outcome. (P4.2 — push-to-deploy.)
	// event  = "push" | "installation" | "ping" | other X-GitHub-Event value
	// result = "ok" | "bad_signature" | "replay" | "no_match" | "disabled" | "error"
	// Lazy *Vec — no series at /metrics until the first delivery of each label set.
	GitHubWebhookReceivedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_github_webhook_received_total",
		Help: "Inbound GitHub App webhook deliveries by event and result",
	}, []string{"event", "result"})

	// GitHubPushDeployTotal counts push→auto-redeploy outcomes (P4.2).
	// result = "enqueued" | "rate_limited" | "no_connection" | "error"
	GitHubPushDeployTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_github_pushdeploy_total",
		Help: "GitHub App push-to-deploy outcomes by result",
	}, []string{"result"})

	// WebhookAuthFailuresTotal counts inbound webhook auth failures across
	// every email-provider webhook surface (Brevo HMAC + SES/SNS RSA).
	// Distinguishes:
	//   webhook = "brevo_hmac" | "ses_sns" | "brevo_url_secret"
	//   reason  = "secret_unset"        — operator hasn't deployed the
	//                                     corresponding secret env var
	//             "signature_mismatch"  — secret IS configured, inbound
	//                                     payload's HMAC / RSA / TopicArn
	//                                     did not match
	//             "missing_signature"   — inbound payload carries no
	//                                     signature header at all
	//
	// API-19/96/97/98 (QA 2026-05-29): pre-fix every 401 from these routes
	// rolled into a single generic "invalid_signature" code, so operators
	// could not distinguish "we forgot to deploy the secret" from "the
	// provider rotated their key" from "drive-by traffic" without
	// hand-grepping log lines. NR alert on
	// rate(instant_webhook_auth_failures_total{reason="secret_unset"}[5m]) > 0
	// fires within 5 min of a deploy that drops the env var; signature_mismatch
	// fires on real attacks or key rotations.
	//
	// Cardinality bound: {brevo_hmac, ses_sns, brevo_url_secret} x
	// {secret_unset, signature_mismatch, missing_signature} = 9 series.
	WebhookAuthFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_webhook_auth_failures_total",
		Help: "Inbound webhook auth failures by webhook (brevo_hmac/ses_sns/brevo_url_secret) and reason (secret_unset/signature_mismatch/missing_signature). API-19/96/97/98 (QA 2026-05-29).",
	}, []string{"webhook", "reason"})

	// MagicLinkEmailRateLimited counts POST /auth/email/start requests
	// silently absorbed by the per-email rate limiter. B4-F1 (BugBash
	// 2026-05-20): the per-email limit responds 202 (identical to the
	// success path) to deny attackers an enumeration signal — but that
	// also denied OPERATORS any signal a real abuser was hammering one
	// address. This counter is the operator-side telemetry: a rising
	// rate should fire an NR alert ("someone is flood-testing magic-link
	// requests for a single mailbox").
	MagicLinkEmailRateLimited = promauto.NewCounter(prometheus.CounterOpts{
		Name: "instant_magic_link_email_rate_limited_total",
		Help: "POST /auth/email/start requests silently absorbed by the per-email rate limit (B4-F1, BugBash 2026-05-20).",
	})

	// RazorpayWebhookTeamNotFound counts /razorpay/webhook deliveries that
	// pass signature verification BUT reference a team that does not exist
	// (notes.team_id misses or matches no team row → ErrTeamNotFound).
	// Wave-3 chaos verify P3 (2026-05-21): the unauthorized (signature
	// failed) counter already exists; this one is the signature-passed
	// counterpart that surfaces probing / dashboard-typo / deleted-team /
	// synthetic-chaos signals. Counter rather than Gauge — each occurrence is
	// independently meaningful for the NR rate alert. No labels: the metric
	// is informational and we deliberately do not break out by team_id or
	// event_type (those land in the matching audit_log row + slog line).
	RazorpayWebhookTeamNotFound = promauto.NewCounter(prometheus.CounterOpts{
		Name: "razorpay_webhook_team_not_found_total",
		Help: "Razorpay webhooks whose signature verified but whose notes.team_id (or subscription_id fallback) referenced a non-existent team — operator signal for typo/deleted-team/probing (Wave-3 chaos verify P3, 2026-05-21).",
	})

	// readyzCheckStatusGauge is the per-component readiness status for
	// /readyz. Value: 1 = ok, 0.5 = degraded, 0 = failed. Labels:
	//   - service:  "instant-api", "instant-worker", "instant-provisioner"
	//   - check:    "platform_db", "brevo", "razorpay", "do_spaces",
	//               "provisioner_grpc", "redis", "customer_db", etc.
	// The NR alert reads `readyz_check_status{service=~".+"} == 0` over
	// the last 5 minutes — a sustained failed state pages the operator.
	// Brevo silent-rejection (2026-05-20) would have surfaced here as
	// `readyz_check_status{service="instant-api",check="brevo"}` flipping
	// from 1 → 0.5 the moment the api-key went bad.
	readyzCheckStatusGauge = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "readyz_check_status",
		Help: "Per-component readiness status (1=ok, 0.5=degraded, 0=failed). Set by /readyz on every probe.",
	}, []string{"service", "check"})

	// PGPoolInUse and PGPoolWaiting expose the live state of api's
	// *sql.DB pool. Set on a 5-second tick from main.go (see
	// startPGPoolStatsExporter).
	//
	// Wave-3 chaos verify (2026-05-21): a 50-concurrent /db/new burst
	// exhausted the DigitalOcean Managed Postgres connection pool and
	// caused worker's event_email_forwarder to fail with "remaining
	// connection slots are reserved for non-replication superuser
	// connections". The api pool was at 25/10 with handlers holding
	// connections through the full provisioner gRPC round-trip (~160s
	// on the worst-case path). Without these gauges the saturation was
	// invisible in /metrics — operators had to infer it from worker
	// errors after the fact.
	//
	// Labels:
	//   - pool: "platform_db" (api's main pool) — additional pools may
	//     be added later (per-customer-DB connections are not pooled
	//     and so are not surfaced here).
	//
	// NR alert: `instant_pg_pool_in_use / instant_pg_pool_max > 0.8`
	// for 5min — pages the operator before the pool actually saturates.
	PGPoolInUse = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_in_use",
		Help: "Postgres connections currently in use by the api process pool. Sampled every 5s. Wave-3 chaos verify 2026-05-21.",
	}, []string{"pool"})

	PGPoolIdle = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_idle",
		Help: "Postgres connections currently idle in the api process pool. Sampled every 5s.",
	}, []string{"pool"})

	PGPoolOpen = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_open",
		Help: "Postgres connections currently open (in-use + idle) in the api process pool. Sampled every 5s.",
	}, []string{"pool"})

	PGPoolMax = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_max",
		Help: "Postgres connections ceiling (SetMaxOpenConns). Constant for the process lifetime; re-published every 5s as a safety belt.",
	}, []string{"pool"})

	PGPoolWaitCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_wait_count",
		Help: "Cumulative count of connection-acquisition waits since process start (sql.DBStats.WaitCount). A flat line == no saturation; a steepening slope == pool saturated.",
	}, []string{"pool"})

	PGPoolWaitDurationSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "instant_pg_pool_wait_duration_seconds",
		Help: "Cumulative time spent waiting for a connection since process start, in seconds (sql.DBStats.WaitDuration). Pairs with instant_pg_pool_wait_count.",
	}, []string{"pool"})

	// AnalyticsEmitFailed counts behavioral-intelligence custom events
	// (common/analyticsevent — InstantFunnel etc.) that were DROPPED rather than
	// reaching the analytics sink. The dominant reason today is "nil_app": the
	// New Relic sink had no *newrelic.Application (NR not configured) — which is
	// the expected steady state until ANALYTICS_BACKEND=newrelic + a license key
	// are wired, so this counter sitting at a flat non-zero is benign in that
	// configuration. A SUDDEN climb after NR is configured means the bridge is
	// dropping real funnel events. Lazy *Vec: not visible at /metrics until the
	// first label is observed (a dropped emit). Labelled by reason so the alert
	// can distinguish "misconfigured" (nil_app) from a sink-side reject.
	AnalyticsEmitFailed = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "instant_analytics_emit_failed_total",
		Help: "Behavioral-intelligence custom events dropped before reaching the analytics sink, by reason.",
	}, []string{"reason"})
)

// ReadyzCheckStatus updates the gauge for one check in this service.
// Wired from the readyzMetrics adapter in handlers/readyz.go. The
// service label is omitted from the caller's signature and stamped by
// this helper so a future refactor that adds a new service can't
// accidentally publish under the wrong label.
//
// service is "instant-api" because this is the api repo; sibling repos
// have their own metrics.ReadyzCheckStatus with their own service label
// (or call the gauge directly via WithLabelValues).
func ReadyzCheckStatus(check string, value float64) {
	readyzCheckStatusGauge.WithLabelValues("instant-api", check).Set(value)
}

// StatusClass converts an HTTP status code to a label-safe class string.
// Returns "2xx", "4xx", "5xx", or "other".
func StatusClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "other"
	}
}
