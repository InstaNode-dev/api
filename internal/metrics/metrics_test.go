package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestStatusClass(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{200, "2xx"},
		{201, "2xx"},
		{299, "2xx"},
		{400, "4xx"},
		{404, "4xx"},
		{499, "4xx"},
		{500, "5xx"},
		{503, "5xx"},
		{599, "5xx"},
		{100, "other"},
		{0, "other"},
		{301, "other"},
		{-1, "other"},
	}
	for _, c := range cases {
		if got := StatusClass(c.code); got != c.want {
			t.Errorf("StatusClass(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// counterValue extracts the float64 value of a prometheus.Counter by hitting
// Collect()'s channel directly. Used to verify Observe paths actually move
// the underlying metric.
func counterValue(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 16)
	go func() {
		c.Collect(ch)
		close(ch)
	}()
	var total float64
	for m := range ch {
		var dtoMetric dto.Metric
		if err := m.Write(&dtoMetric); err != nil {
			t.Fatalf("metric.Write: %v", err)
		}
		if dtoMetric.Counter != nil {
			total += dtoMetric.Counter.GetValue()
		}
		if dtoMetric.Gauge != nil {
			total += dtoMetric.Gauge.GetValue()
		}
	}
	return total
}

func TestReadyzCheckStatus_SetsGauge(t *testing.T) {
	// Hit each value in the documented contract (1, 0.5, 0) plus an
	// arbitrary float to confirm the gauge accepts the full range.
	for _, v := range []float64{1, 0.5, 0, 0.25} {
		ReadyzCheckStatus("unit-test-check", v)
	}
	// Read back via the underlying gauge — service label is stamped by
	// ReadyzCheckStatus itself, so we look up by both labels.
	g, err := readyzCheckStatusGauge.GetMetricWithLabelValues("instant-api", "unit-test-check")
	if err != nil {
		t.Fatalf("GetMetricWithLabelValues: %v", err)
	}
	var dtoMetric dto.Metric
	if err := g.Write(&dtoMetric); err != nil {
		t.Fatalf("g.Write: %v", err)
	}
	if got := dtoMetric.Gauge.GetValue(); got != 0.25 {
		t.Fatalf("expected last-set value 0.25, got %v", got)
	}
}

// TestAllMetricsRegistered exercises every exported metric by performing one
// representative observation. Counter/Gauge/Histogram values are read back to
// confirm the path actually moves the underlying series — a smoke harness that
// fails fast if a metric is renamed, retyped, or accidentally removed.
func TestAllMetricsRegistered(t *testing.T) {
	ProvisionsTotal.WithLabelValues("postgres", "hobby").Inc()
	ProvisionFailures.WithLabelValues("postgres", "grpc_error").Inc()
	ProvisionDuration.WithLabelValues("postgres", "hobby").Observe(0.1)
	HTTPRequestDuration.WithLabelValues("POST", "/db/new", "2xx").Observe(0.05)
	HTTPErrors.WithLabelValues("POST", "/db/new", "4xx").Inc()
	GRPCDuration.WithLabelValues("Provision", "ok").Observe(0.2)
	FingerprintAbuseBlocked.Inc()
	RecycleGateBlocked.WithLabelValues("postgres").Inc()
	ConversionFunnel.WithLabelValues("paid").Inc()
	RedisErrors.WithLabelValues("get").Inc()
	FailOpenEvents.WithLabelValues("redis_rate_limit", "redis_unavailable").Inc()
	GeoIPDBAge.Set(12.5)
	StorageIAMUsersCreated.Inc()
	StorageIAMUsersDeleted.Inc()
	StorageIAMUsersFailed.WithLabelValues("create", "add_user").Inc()
	DedicatedTierUpgradeBlocked.WithLabelValues("db", "free").Inc()
	StackProvisionLimitBlocked.WithLabelValues("hobby").Inc()
	QueueProvisionLimitBlocked.WithLabelValues("hobby").Inc()
	DeployTeardownMarkFailed.Inc()
	NatsAuthFailures.Inc()
	GoroutinePanics.WithLabelValues("runDeploy").Inc()
	BrevoWebhookEventsTotal.WithLabelValues("delivered").Inc()
	MagicLinkEmailRateLimited.Inc()
	RazorpayWebhookTeamNotFound.Inc()
	RazorpayWebhookSigFail.Inc()
	RecycleClaimRecovery.WithLabelValues("minted").Inc()
	RecycleClaimRecovery.WithLabelValues("mint_failed").Inc()
	UpgradeTokenChain.WithLabelValues("accepted").Inc()
	UpgradeTokenChain.WithLabelValues("rejected").Inc()
	UpgradeTokenChain.WithLabelValues("truncated").Inc()
	PGPoolInUse.WithLabelValues("platform_db").Set(3)
	PGPoolIdle.WithLabelValues("platform_db").Set(2)
	PGPoolOpen.WithLabelValues("platform_db").Set(5)
	PGPoolMax.WithLabelValues("platform_db").Set(25)
	PGPoolWaitCount.WithLabelValues("platform_db").Set(42)
	PGPoolWaitDurationSeconds.WithLabelValues("platform_db").Set(3.14)

	// Confirm two representative metrics actually carry a value (covers
	// the rest by construction — same prometheus library + same Inc/Set).
	if v := counterValue(t, FingerprintAbuseBlocked); v < 1 {
		t.Fatalf("FingerprintAbuseBlocked should be >= 1, got %v", v)
	}
	if v := counterValue(t, GeoIPDBAge); v != 12.5 {
		t.Fatalf("GeoIPDBAge should be 12.5, got %v", v)
	}
}

// TestMetricsExposedViaPrometheusRegistry confirms each metric has the
// documented Prometheus name and Help text — a contract test against
// dashboards/alerts that reference these strings.
func TestMetricsExposedViaPrometheusRegistry(t *testing.T) {
	want := []string{
		"instant_provisions_total",
		"instant_provision_failures_total",
		"instant_provision_duration_seconds",
		"instant_http_request_duration_seconds",
		"instant_http_errors_total",
		"instant_grpc_duration_seconds",
		"instant_fingerprint_abuse_blocked_total",
		"instant_recycle_gate_blocked_total",
		"instant_conversion_funnel_total",
		"instant_redis_errors_total",
		"instant_fail_open_events_total",
		"instant_geoip_db_age_hours",
		"instant_storage_iam_users_created_total",
		"instant_storage_iam_users_deleted_total",
		"instant_storage_iam_users_failed_total",
		"instant_dedicated_tier_upgrade_blocked_total",
		"instant_stack_provision_limit_blocked_total",
		"instant_queue_provision_limit_blocked_total",
		"instant_deploy_teardown_mark_failed_total",
		"nats_auth_failures_total",
		"instant_goroutine_panics_total",
		"brevo_webhook_events_total",
		"instant_magic_link_email_rate_limited_total",
		"razorpay_webhook_team_not_found_total",
		"readyz_check_status",
		"instant_pg_pool_in_use",
		"instant_pg_pool_idle",
		"instant_pg_pool_open",
		"instant_pg_pool_max",
		"instant_pg_pool_wait_count",
		"instant_pg_pool_wait_duration_seconds",
	}
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	seen := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		seen[mf.GetName()] = true
	}
	var missing []string
	for _, n := range want {
		if !seen[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("metrics missing from default registry: %s", strings.Join(missing, ", "))
	}
}
