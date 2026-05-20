package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"google.golang.org/grpc/credentials"
)

// InitTracer configures the global OpenTelemetry tracer provider.
//
// Endpoint selection (in order of precedence):
//  1. otlpEndpoint argument (typically os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
//  2. if empty → tracing disabled (noop), return a no-op shutdown
//
// TLS vs plaintext is auto-detected from the scheme: an `https://` prefix
// (or an endpoint targeting the well-known NR OTLP host `otlp.*nr-data.net`)
// uses TLS; everything else (no scheme, `http://`, an in-cluster host like
// `otel-collector:4317`) falls back to plaintext for local dev.
//
// New Relic auth: when NEW_RELIC_LICENSE_KEY is set (and non-sentinel), it
// is sent as the `api-key` gRPC header on every export — this is the NR
// OTLP ingest contract. When unset/empty/`CHANGE_ME`, we still construct
// a working exporter (it just won't be accepted by NR) and log a WARN so
// the operator knows tracing is configured-but-unauthenticated.
//
// Returns shutdown which should be deferred; shutdown is a no-op when
// tracing is disabled. NEVER crashes — every failure mode falls back to
// a no-op shutdown so a misconfigured tracer can never block service boot.
//
// Historical note (2026-05-20 P0-2): the prior implementation called
// `otlptracegrpc.WithInsecure()` against the TLS endpoint
// `https://otlp.nr-data.net:4317` and never sent the NR `api-key` header.
// Result: every export silently failed (`http2 frame too large`), every
// log line had `trace_id=""`. The TLS-by-scheme + NR-key-header pair
// below is the fix; do not revert.
func InitTracer(serviceName, otlpEndpoint string) func(context.Context) error {
	raw := strings.TrimSpace(otlpEndpoint)
	if raw == "" {
		return func(context.Context) error { return nil }
	}

	if s := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); s != "" {
		serviceName = s
	}

	useTLS := shouldUseTLS(raw)
	ep := stripScheme(raw)

	licenseKey := strings.TrimSpace(os.Getenv("NEW_RELIC_LICENSE_KEY"))
	if licenseKey == "" || licenseKey == "CHANGE_ME" {
		slog.Warn("telemetry.nr_license_missing",
			"endpoint", ep,
			"detail", "OTLP exporter constructed but NEW_RELIC_LICENSE_KEY is empty/sentinel; exports will be rejected by NR")
		licenseKey = ""
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(ep),
	}
	if useTLS {
		opts = append(opts,
			otlptracegrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{
				MinVersion: tls.VersionTLS12,
			})),
		)
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	if licenseKey != "" {
		// NR OTLP requires this header on every request; without it the
		// ingest path returns UNAUTHENTICATED and the exporter silently
		// drops every span.
		opts = append(opts, otlptracegrpc.WithHeaders(map[string]string{
			"api-key": licenseKey,
		}))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exporter, err := otlptracegrpc.New(ctx, opts...)
	if err != nil {
		slog.Error("telemetry.otlp_exporter_failed", "error", err, "endpoint", ep, "tls", useTLS)
		return func(context.Context) error { return nil }
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		slog.Error("telemetry.resource_failed", "error", err)
		_ = exporter.Shutdown(ctx)
		return func(context.Context) error { return nil }
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	slog.Info("telemetry.tracer_initialized",
		"service", serviceName,
		"endpoint", ep,
		"tls", useTLS,
		"nr_auth", licenseKey != "")

	return func(shutdownCtx context.Context) error {
		ctx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("telemetry shutdown: %w", err)
		}
		return nil
	}
}

// shouldUseTLS returns true when the OTLP endpoint should be dialed over
// TLS. Heuristics, in order:
//  1. explicit `https://` scheme → TLS
//  2. explicit `http://` scheme → plaintext
//  3. host matches `otlp.*nr-data.net` (NR's OTLP ingest hosts, all TLS) → TLS
//  4. host ends in `:443` → TLS
//  5. otherwise (no scheme, in-cluster collector, etc) → plaintext
//
// Exported only for tests.
func shouldUseTLS(endpoint string) bool {
	e := strings.ToLower(strings.TrimSpace(endpoint))
	if strings.HasPrefix(e, "https://") {
		return true
	}
	if strings.HasPrefix(e, "http://") {
		return false
	}
	host := stripScheme(e)
	// Bare host[:port] — sniff for NR's well-known OTLP hosts and the
	// 443 port suffix.
	if strings.Contains(host, "nr-data.net") {
		return true
	}
	if strings.HasSuffix(host, ":443") {
		return true
	}
	return false
}

// stripScheme removes a leading `http://` or `https://` from the endpoint,
// returning the bare `host:port` form that otlptracegrpc.WithEndpoint
// expects.
func stripScheme(endpoint string) string {
	e := strings.TrimSpace(endpoint)
	e = strings.TrimPrefix(e, "https://")
	e = strings.TrimPrefix(e, "http://")
	return e
}
