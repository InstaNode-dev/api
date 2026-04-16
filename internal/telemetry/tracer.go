package telemetry

import (
	"context"
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
)

// InitTracer configures the global OpenTelemetry tracer provider.
// When otlpEndpoint is empty, the SDK default noop provider is used (fail open).
// Returns shutdown which should be deferred; shutdown is a no-op when tracing is disabled.
func InitTracer(serviceName, otlpEndpoint string) func(context.Context) error {
	ep := strings.TrimSpace(otlpEndpoint)
	if ep == "" {
		return func(context.Context) error { return nil }
	}

	if s := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); s != "" {
		serviceName = s
	}

	ep = strings.TrimPrefix(ep, "https://")
	ep = strings.TrimPrefix(ep, "http://")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(ep),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		slog.Error("telemetry.otlp_exporter_failed", "error", err, "endpoint", ep)
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

	return func(shutdownCtx context.Context) error {
		ctx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if err := tp.Shutdown(ctx); err != nil {
			return fmt.Errorf("telemetry shutdown: %w", err)
		}
		return nil
	}
}
