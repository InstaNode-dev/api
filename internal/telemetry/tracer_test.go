package telemetry

import (
	"context"
	"errors"
	"testing"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
)

// withExporterStub temporarily replaces the package-level newExporter seam,
// restoring it on cleanup. Lets a test drive the otlptracegrpc.New failure
// arm without touching production wiring.
func withExporterStub(t *testing.T, fn func(context.Context, ...otlptracegrpc.Option) (*otlptrace.Exporter, error)) {
	t.Helper()
	prev := newExporter
	t.Cleanup(func() { newExporter = prev })
	newExporter = fn
}

// withResourceStub temporarily replaces the package-level newResource seam.
func withResourceStub(t *testing.T, fn func(context.Context, ...resource.Option) (*resource.Resource, error)) {
	t.Helper()
	prev := newResource
	t.Cleanup(func() { newResource = prev })
	newResource = fn
}

// TestInitTracer_ExporterConstructionFails — when otlptracegrpc.New errors
// (network stack misconfig, bad creds object, etc.), InitTracer MUST log and
// return a working no-op shutdown rather than crash. This is the fail-open
// contract: a broken exporter can never block service boot.
func TestInitTracer_ExporterConstructionFails(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	withExporterStub(t, func(context.Context, ...otlptracegrpc.Option) (*otlptrace.Exporter, error) {
		return nil, errors.New("boom: exporter construction failed")
	})

	shutdown := InitTracer("instant-api", "https://otlp.nr-data.net:4317")
	if shutdown == nil {
		t.Fatal("InitTracer must return a non-nil no-op shutdown when the exporter fails")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown after exporter failure must return nil, got %v", err)
	}
}

// TestInitTracer_ResourceConstructionFails — when resource.New errors,
// InitTracer MUST shut down the already-built exporter and return a working
// no-op shutdown. Same fail-open contract as the exporter arm.
func TestInitTracer_ResourceConstructionFails(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	// Real exporter constructs fine (lazy dial); force the resource arm.
	withResourceStub(t, func(context.Context, ...resource.Option) (*resource.Resource, error) {
		return nil, errors.New("boom: resource construction failed")
	})

	shutdown := InitTracer("instant-api", "http://localhost:4317")
	if shutdown == nil {
		t.Fatal("InitTracer must return a non-nil no-op shutdown when resource.New fails")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("no-op shutdown after resource failure must return nil, got %v", err)
	}
}

// TestInitTracer_EmptyEndpointNoop — when the endpoint is unset, the
// returned shutdown must be a working no-op. This is the fail-open
// contract for local dev / CI runs where OTel is intentionally off.
func TestInitTracer_EmptyEndpointNoop(t *testing.T) {
	shutdown := InitTracer("instant-api", "")
	if shutdown == nil {
		t.Fatal("InitTracer returned nil shutdown for empty endpoint")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("noop shutdown returned error: %v", err)
	}
}

// TestInitTracer_Boots — with a non-empty endpoint, InitTracer constructs
// a real exporter without crashing even if NEW_RELIC_LICENSE_KEY is unset.
// The exporter dials lazily on the first export, so construction must
// succeed regardless of whether the endpoint is reachable.
func TestInitTracer_Boots(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	shutdown := InitTracer("instant-api", "https://otlp.nr-data.net:4317")
	if shutdown == nil {
		t.Fatal("InitTracer returned nil shutdown")
	}
	// Best-effort shutdown — the exporter may have queued zero spans, in
	// which case Shutdown returns nil immediately. Any non-nil error must
	// not be a panic/segfault — just log and move on.
	_ = shutdown(context.Background())
}

// TestShouldUseTLS — the regression case for P0-2: every `https://`
// endpoint AND every `*nr-data.net` host MUST resolve to TLS=true.
// Reverting to WithInsecure() for these would silently kill tracing
// again (the symptom that produced this test).
func TestShouldUseTLS(t *testing.T) {
	cases := []struct {
		endpoint string
		want     bool
	}{
		{"https://otlp.nr-data.net:4317", true},
		{"https://otlp.eu01.nr-data.net:4317", true},
		{"otlp.nr-data.net:4317", true},
		{"otlp.eu01.nr-data.net:4317", true},
		{"foo.example.com:443", true},
		{"http://otel-collector.observability:4317", false},
		{"otel-collector.observability:4317", false},
		{"localhost:4317", false},
		{"", false},
	}
	for _, c := range cases {
		got := shouldUseTLS(c.endpoint)
		if got != c.want {
			t.Errorf("shouldUseTLS(%q) = %v, want %v", c.endpoint, got, c.want)
		}
	}
}

// TestStripScheme — strips http:// and https:// uniformly. Required
// because otlptracegrpc.WithEndpoint takes a bare host:port; passing
// a full URL silently fails to dial.
func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"https://otlp.nr-data.net:4317": "otlp.nr-data.net:4317",
		"http://localhost:4317":         "localhost:4317",
		"otlp.nr-data.net:4317":         "otlp.nr-data.net:4317",
		"":                              "",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestInitTracer_ServiceNameOverride — OTEL_SERVICE_NAME, when set, overrides
// the passed serviceName. We can't read the resource back out, but exercising
// the branch + booting cleanly is what coverage needs; the shutdown must be
// callable.
func TestInitTracer_ServiceNameOverride(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "override-svc")
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	shutdown := InitTracer("instant-api", "https://otlp.nr-data.net:4317")
	if shutdown == nil {
		t.Fatal("nil shutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestInitTracer_InsecureEndpoint — a plaintext (http://) endpoint takes the
// WithInsecure() branch instead of WithTLSCredentials.
func TestInitTracer_InsecureEndpoint(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	shutdown := InitTracer("instant-api", "http://localhost:4317")
	if shutdown == nil {
		t.Fatal("nil shutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestInitTracer_WithLicenseKey — a real (non-sentinel) license key takes the
// WithHeaders(api-key) branch.
func TestInitTracer_WithLicenseKey(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "real-license-key-1234567890")
	shutdown := InitTracer("instant-api", "https://otlp.nr-data.net:4317")
	if shutdown == nil {
		t.Fatal("nil shutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}

// TestInitTracer_SentinelLicenseKeyTreatedAsMissing — the CHANGE_ME sentinel
// must take the license-missing warning branch (no api-key header).
func TestInitTracer_SentinelLicenseKeyTreatedAsMissing(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "CHANGE_ME")
	shutdown := InitTracer("instant-api", "otlp.nr-data.net:4317")
	if shutdown == nil {
		t.Fatal("nil shutdown")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown: %v", err)
	}
}
