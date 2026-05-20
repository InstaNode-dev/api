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
)

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
