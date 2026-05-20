package telemetry

import (
	"context"
	"testing"
)

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
