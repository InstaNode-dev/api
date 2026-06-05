package router_test

// analytics_wiring_test.go — covers the WS4 analytics emitter construction in
// router.go (wireAnalyticsEmitter): backend selection from ANALYTICS_BACKEND,
// the inert noop default, unknown-backend degrade, and the New Relic
// failure-hook → Prometheus counter bridge. We exercise the exported alias
// rather than the full router.New(...) (which needs Postgres + Redis + gRPC).

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"instant.dev/common/analyticsevent"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/metrics"
	"instant.dev/internal/router"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatalf("counter Write: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestWireAnalyticsEmitter_DefaultNoop(t *testing.T) {
	t.Cleanup(func() { handlers.SetAnalyticsEmitter(analyticsevent.NewNoop()) })

	e := router.ExportedWireAnalyticsEmitter(&config.Config{AnalyticsBackend: "noop"}, nil)
	if e == nil {
		t.Fatal("wireAnalyticsEmitter returned nil emitter")
	}
	if e.Name() != analyticsevent.BackendNoop {
		t.Fatalf("noop backend Name = %q, want %q", e.Name(), analyticsevent.BackendNoop)
	}
	// The inert default must not panic on emit.
	e.Record(context.Background(), analyticsevent.EventFunnel, map[string]any{analyticsevent.AttrTier: "anonymous"})
}

func TestWireAnalyticsEmitter_UnknownBackendDegradesToNoop(t *testing.T) {
	t.Cleanup(func() { handlers.SetAnalyticsEmitter(analyticsevent.NewNoop()) })

	// An unrecognised backend must not panic — Factory returns an advisory error
	// and a usable noop emitter; wireAnalyticsEmitter logs and proceeds.
	e := router.ExportedWireAnalyticsEmitter(&config.Config{AnalyticsBackend: "totally-unknown"}, nil)
	if e.Name() != analyticsevent.BackendNoop {
		t.Fatalf("unknown backend should degrade to noop, got %q", e.Name())
	}
}

func TestWireAnalyticsEmitter_NewRelicNilAppFiresFailureHook(t *testing.T) {
	t.Cleanup(func() { handlers.SetAnalyticsEmitter(analyticsevent.NewNoop()) })

	before := counterValue(t, metrics.AnalyticsEmitFailed.WithLabelValues("nil_app"))

	// backend=newrelic with a nil *newrelic.Application: the nr sink wires the
	// failure hook wireAnalyticsEmitter passes. An emit drops with reason
	// "nil_app" and must increment instant_analytics_emit_failed_total.
	e := router.ExportedWireAnalyticsEmitter(&config.Config{AnalyticsBackend: "newrelic"}, nil)
	if e.Name() != analyticsevent.BackendNewRelic {
		t.Fatalf("newrelic backend Name = %q, want %q", e.Name(), analyticsevent.BackendNewRelic)
	}
	e.Record(context.Background(), analyticsevent.EventFunnel, map[string]any{
		analyticsevent.AttrFunnelStep: analyticsevent.FunnelStepProvision,
	})

	after := counterValue(t, metrics.AnalyticsEmitFailed.WithLabelValues("nil_app"))
	if after <= before {
		t.Fatalf("failure-hook counter did not increment: before=%v after=%v", before, after)
	}
}
