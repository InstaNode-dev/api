// Command provisioner-obs-scaffold is a reference wiring of observability
// for the instant.dev/provisioner gRPC service (track 5 of 8 in the 2026-05-12
// observability rollout — see OBSERVABILITY-PLAN-2026-05-12.md at the repo
// root).
//
// SCOPE NOTE. The real provisioner service lives in a sibling repo
// (github.com/InstaNode-dev/provisioner) and that repo's main.go is the one
// that actually runs in k8s. This file is a faithful, drop-in-shaped
// reference that demonstrates exactly how slog, the New Relic Go agent,
// the nrgrpc UnaryServerInterceptor, and the HTTP sidecar fit together —
// so the same five-line diff can be applied to the real provisioner's
// main.go once this PR is reviewed.
//
// Why scaffold here. The observability rollout dispatched eight parallel
// agents, each given a per-track worktree of the api repo. The track-5
// brief listed file paths under a `provisioner/` prefix that assumed a
// monorepo layout. The api repo isn't a monorepo — provisioner is its own
// repo. Rather than touch the real provisioner repo from a worktree
// configured for api (which would violate filesystem isolation between
// parallel agents), this PR stages the changes under a clearly-marked
// `provisioner/` subdir for review. The follow-up is a copy of these four
// files into the real provisioner repo.
//
// What this binary does when run. It is a minimal stand-in: it boots
// observability and starts the HTTP sidecar on :8092, then blocks on a
// signal. It does NOT serve gRPC — that lives in the real repo. Running
// it locally is useful only to verify the /healthz JSON shape.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/newrelic/go-agent/v3/integrations/nrgrpc"
	"github.com/newrelic/go-agent/v3/newrelic"
	"google.golang.org/grpc"

	"instant.dev/provisioner/internal/_obs_stubs/logctx"
	"instant.dev/provisioner/internal/server"
)

// healthzAddr is the listen address for the HTTP sidecar. Port 8092 was
// chosen by the rollout plan because it doesn't collide with the gRPC port
// (50051), the api Fiber port (8080), worker (no fixed port), Prometheus
// scrapers in our cluster (9090, 9091, 9100), or any of the data-namespace
// services. See TestHealthzPortNoCollisionWithGRPC for the assertion.
const healthzAddr = ":8092"

// initNewRelic boots the New Relic Go agent. It is fail-open: an empty
// license key (the common case in dev) or any initialization error logs a
// warning and returns nil. Callers must handle a nil *newrelic.Application
// — the nrgrpc interceptor does so safely.
func initNewRelic() *newrelic.Application {
	licenseKey := os.Getenv("NEW_RELIC_LICENSE_KEY")
	if licenseKey == "" {
		slog.Warn("newrelic.disabled — NEW_RELIC_LICENSE_KEY not set")
		return nil
	}

	appName := os.Getenv("NEW_RELIC_APP_NAME")
	if appName == "" {
		appName = "instant-provisioner"
	}

	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName(appName),
		newrelic.ConfigLicense(licenseKey),
		newrelic.ConfigDistributedTracerEnabled(true),
		newrelic.ConfigAppLogForwardingEnabled(true),
	)
	if err != nil {
		// Fail-open: log and continue. A provisioning outage because the NR
		// agent couldn't dial home would be a wildly disproportionate failure
		// mode for an observability dependency.
		slog.Warn("newrelic.init_failed", "error", err)
		return nil
	}
	return app
}

// newGRPCServer constructs a grpc.Server with the NR unary interceptor
// registered. The interceptor:
//
//  1. Reads incoming W3C TraceContext from gRPC metadata (the api side
//     already propagates this via otelgrpc.NewClientHandler — see
//     internal/provisioner/client.go in the api repo for the matching
//     side). NR's nrgrpc.UnaryServerInterceptor automatically picks it up
//     and opens a distributed-trace child span.
//
//  2. Pulls the trace ID out of the incoming span and stashes it on ctx
//     via logctx.WithTraceID so any downstream slog calls in the gRPC
//     handler log lines carry the propagated trace_id field.
//
// The wrapping interceptor below chains around nrgrpc's so that step 2
// runs *after* nrgrpc has populated the NR transaction in ctx.
func newGRPCServer(nrApp *newrelic.Application) *grpc.Server {
	return grpc.NewServer(grpc.UnaryInterceptor(
		composeTraceIDInjector(nrgrpc.UnaryServerInterceptor(nrApp)),
	))
}

// composeTraceIDInjector wraps an inner interceptor (typically
// nrgrpc.UnaryServerInterceptor) so that after the inner one has opened the
// NR transaction on ctx, we stamp the trace ID onto ctx via logctx for
// downstream slog calls. Extracted to package-private function so tests can
// invoke it without standing up a real gRPC server.
func composeTraceIDInjector(inner grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		wrapped := func(nrCtx context.Context, nrReq any) (any, error) {
			return handler(stampTraceIDFromNR(nrCtx), nrReq)
		}
		return inner(ctx, req, info, wrapped)
	}
}

// stampTraceIDFromNR looks up the NR transaction on ctx (placed there by
// nrgrpc.UnaryServerInterceptor) and, if present, copies its trace ID onto
// ctx via logctx.WithTraceID. Safe to call when no NR transaction is on
// ctx — returns ctx unchanged.
//
// Split out of composeTraceIDInjector to be unit-testable: a test can
// pre-populate ctx with newrelic.NewContext(ctx, txn) and assert the
// trace_id ends up on the returned ctx. Tests against the *bare* function
// (without spinning up a gRPC server) keep CI fast.
func stampTraceIDFromNR(ctx context.Context) context.Context {
	txn := newrelic.FromContext(ctx)
	if txn == nil {
		return ctx
	}
	md := txn.GetTraceMetadata()
	if md.TraceID == "" {
		return ctx
	}
	return logctx.WithTraceID(ctx, md.TraceID)
}

// startHealthzSidecar starts the HTTP server on healthzAddr in a goroutine.
// Returns the *http.Server so the caller can shut it down cleanly. The
// listener errors are logged but never crash the process — losing /healthz
// should not take down provisioning.
func startHealthzSidecar() *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/healthz", server.HealthzHandler())

	srv := &http.Server{
		Addr:              healthzAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("healthz.listening", "addr", healthzAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("healthz.serve_failed", "error", err)
		}
	}()

	return srv
}

func main() {
	// First action: install the obs-enriching slog handler as the default
	// so every log line from boot onward carries service/commit_id/build_time.
	// The real provisioner main.go has NO slog default set today — this is
	// the inconsistency the plan flagged.
	slog.SetDefault(slog.New(logctx.NewHandler(
		"provisioner",
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelInfo,
		}),
	)))

	nrApp := initNewRelic()
	defer func() {
		if nrApp != nil {
			nrApp.Shutdown(10 * time.Second)
		}
	}()

	// Construct the gRPC server with NR + trace-id-injection interceptors.
	// In the real provisioner the result is passed to
	// provisionerv1.RegisterProvisionerServiceServer and Serve(); here we
	// just demonstrate construction.
	grpcSrv := newGRPCServer(nrApp)
	_ = grpcSrv // referenced by tests; not Serve()d in this scaffold

	healthzSrv := startHealthzSidecar()

	slog.Info("provisioner.scaffold_ready",
		"grpc_port_intended", "50051",
		"healthz_port", healthzAddr,
	)

	// Block until SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthzSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("healthz.shutdown_error", "error", err)
	}
}
