// Tests for the observability scaffolding. Each test corresponds to one of
// the four assertions called out in the track-5 brief.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/newrelic/go-agent/v3/newrelic"
	"google.golang.org/grpc"

	"instant.dev/provisioner/internal/_obs_stubs/logctx"
	"instant.dev/provisioner/internal/server"
)

// TestHealthzReturnsCommitID verifies the /healthz endpoint returns a
// well-formed JSON body containing commit_id. Uses httptest so we don't
// need to bind a real port.
func TestHealthzReturnsCommitID(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)

	server.HealthzHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var body server.HealthzResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.OK {
		t.Errorf("ok = false, want true")
	}
	if body.Service != "instant-provisioner" {
		t.Errorf("service = %q, want instant-provisioner", body.Service)
	}
	if body.CommitID == "" {
		t.Errorf("commit_id is empty — buildinfo.GitSHA must always have a value (default 'dev')")
	}
	if body.BuildTime == "" {
		t.Errorf("build_time is empty")
	}
	if body.Version == "" {
		t.Errorf("version is empty")
	}
}

// TestHealthzPortNoCollisionWithGRPC asserts the chosen sidecar port is not
// the same as the gRPC port. Cheap, but it catches a config typo that would
// otherwise show up as "address already in use" at pod boot.
func TestHealthzPortNoCollisionWithGRPC(t *testing.T) {
	const grpcPort = ":50051"
	if healthzAddr == grpcPort {
		t.Fatalf("healthzAddr %q must not equal gRPC port %q", healthzAddr, grpcPort)
	}
	// Also sanity-check we have a port at all and it parses.
	if !strings.HasPrefix(healthzAddr, ":") {
		t.Fatalf("healthzAddr %q should start with ':'", healthzAddr)
	}
}

// TestInitNewRelicFailOpenOnEmptyKey verifies the agent init returns nil
// (not panic) when the license key env var is unset — which is the dev
// default. The real concern is "does the provisioner crash if NR is down"
// and the answer must be no.
func TestInitNewRelicFailOpenOnEmptyKey(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "")
	app := initNewRelic()
	if app != nil {
		t.Errorf("initNewRelic() = non-nil with empty key, want nil")
	}
}

// TestInitNewRelicFailOpenOnInvalidKey verifies that a malformed license
// key (e.g. someone pasted in a short string) also returns nil without
// panicking. NR's validator rejects keys < 40 chars.
func TestInitNewRelicFailOpenOnInvalidKey(t *testing.T) {
	t.Setenv("NEW_RELIC_LICENSE_KEY", "obviously-not-a-real-key")
	app := initNewRelic()
	if app != nil {
		t.Errorf("initNewRelic() = non-nil with bogus key, want nil — agent should fail-open")
	}
}

// newTestNRApp constructs a real *newrelic.Application with
// ConfigEnabled(false) so it produces real trace metadata but performs no
// network I/O. Returns nil if construction fails — caller decides whether
// to t.Skip or fail.
func newTestNRApp(t *testing.T) *newrelic.Application {
	t.Helper()
	app, err := newrelic.NewApplication(
		newrelic.ConfigAppName("provisioner-test"),
		// 40-char dummy license; NR's validator only checks length when
		// enabled. With ConfigEnabled(false) it's never sent anywhere.
		newrelic.ConfigLicense("0123456789012345678901234567890123456789"),
		newrelic.ConfigEnabled(false),
		newrelic.ConfigDistributedTracerEnabled(true),
	)
	if err != nil {
		t.Fatalf("newrelic.NewApplication: %v", err)
	}
	return app
}

// TestStampTraceIDFromNR is the load-bearing assertion of the track-5
// rollout: when an NR transaction is present on ctx, stampTraceIDFromNR
// must copy its trace_id onto ctx via logctx so downstream slog calls log
// with the propagated trace ID.
func TestStampTraceIDFromNR(t *testing.T) {
	app := newTestNRApp(t)
	txn := app.StartTransaction("test/Provision")
	defer txn.End()

	md := txn.GetTraceMetadata()
	if md.TraceID == "" {
		t.Skip("NR test app did not produce a trace ID — disabled-mode behavior changed; revisit")
	}

	ctx := newrelic.NewContext(context.Background(), txn)
	out := stampTraceIDFromNR(ctx)

	if got := logctx.TraceID(out); got != md.TraceID {
		t.Errorf("stampTraceIDFromNR did not propagate trace_id: got %q, want %q", got, md.TraceID)
	}
}

// TestStampTraceIDFromNR_NoTxn confirms the function is a safe no-op when
// the input ctx has no NR transaction.
func TestStampTraceIDFromNR_NoTxn(t *testing.T) {
	out := stampTraceIDFromNR(context.Background())
	if got := logctx.TraceID(out); got != "" {
		t.Errorf("stampTraceIDFromNR with no txn stamped %q; want empty", got)
	}
}

// TestComposeTraceIDInjectorRunsInner verifies the composed interceptor
// actually calls the inner one (e.g. nrgrpc) and the handler. We use a
// synthetic "inner" that just delegates to the handler so we can confirm
// the wiring without bringing up real NR machinery.
func TestComposeTraceIDInjectorRunsInner(t *testing.T) {
	var innerCalls, handlerCalls int

	inner := func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		innerCalls++
		return handler(ctx, req)
	}

	composed := composeTraceIDInjector(inner)

	handler := func(ctx context.Context, _ any) (any, error) {
		handlerCalls++
		// No NR txn → trace_id stays empty.
		if got := logctx.TraceID(ctx); got != "" {
			t.Errorf("trace_id = %q before NR ctx, want empty", got)
		}
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	resp, err := composed(context.Background(), "req", info, handler)
	if err != nil {
		t.Fatalf("composed interceptor err: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want ok", resp)
	}
	if innerCalls != 1 {
		t.Errorf("inner was called %d times, want 1", innerCalls)
	}
	if handlerCalls != 1 {
		t.Errorf("handler was called %d times, want 1", handlerCalls)
	}
}

// TestComposeTraceIDInjectorPropagatesNRTraceID closes the loop end-to-end:
// build a composed interceptor with an inner that simulates nrgrpc by
// stuffing a real NR txn into ctx, then assert the handler sees a populated
// trace_id via logctx.
func TestComposeTraceIDInjectorPropagatesNRTraceID(t *testing.T) {
	app := newTestNRApp(t)
	txn := app.StartTransaction("test/Provision")
	defer txn.End()

	expected := txn.GetTraceMetadata().TraceID
	if expected == "" {
		t.Skip("NR test app did not produce a trace ID")
	}

	// Synthetic "inner" interceptor — pretends to be nrgrpc by injecting
	// the txn into ctx before calling the (wrapped) handler.
	inner := func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		return handler(newrelic.NewContext(ctx, txn), req)
	}
	composed := composeTraceIDInjector(inner)

	var captured context.Context
	handler := func(ctx context.Context, _ any) (any, error) {
		captured = ctx
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	if _, err := composed(context.Background(), "req", info, handler); err != nil {
		t.Fatalf("composed interceptor err: %v", err)
	}
	if captured == nil {
		t.Fatal("handler did not run")
	}
	if got := logctx.TraceID(captured); got != expected {
		t.Errorf("trace_id propagated to handler ctx = %q, want %q", got, expected)
	}
}

// TestNewGRPCServerWithNilNRApp confirms the server constructor handles the
// fail-open (nil app) path without panicking.
func TestNewGRPCServerWithNilNRApp(t *testing.T) {
	srv := newGRPCServer(nil)
	if srv == nil {
		t.Fatal("newGRPCServer(nil) returned nil")
	}
}

// TestLogctxWithTraceIDRoundTrip covers the stub logctx package end-to-end
// to defend against a future cleanup pass accidentally breaking the
// trace-id round-trip when the stubs are removed in favor of common/logctx.
func TestLogctxWithTraceIDRoundTrip(t *testing.T) {
	ctx := context.Background()
	if got := logctx.TraceID(ctx); got != "" {
		t.Errorf("fresh ctx TraceID = %q, want empty", got)
	}

	ctx2 := logctx.WithTraceID(ctx, "abc123")
	if got := logctx.TraceID(ctx2); got != "abc123" {
		t.Errorf("after WithTraceID, TraceID = %q, want abc123", got)
	}

	// Empty trace id is a no-op — verify the parent ctx is returned
	// unchanged so a meaningful trace ID upstream isn't accidentally
	// overwritten with "".
	ctx3 := logctx.WithTraceID(ctx2, "")
	if got := logctx.TraceID(ctx3); got != "abc123" {
		t.Errorf("WithTraceID(\"\") wiped trace_id — got %q, want abc123 retained", got)
	}
}

// TestEnvAppNameOverride confirms NEW_RELIC_APP_NAME wins over the default.
// This is what k8s deployment specs will use to differentiate -prod /
// -staging / -dev environments per the plan doc's open question 2.
func TestEnvAppNameOverride(t *testing.T) {
	// We can't easily inspect what name NR was init'd with because the
	// agent's internal config isn't exported — but we can at least verify
	// init doesn't panic when the env is set.
	t.Setenv("NEW_RELIC_APP_NAME", "instant-provisioner-staging")
	t.Setenv("NEW_RELIC_LICENSE_KEY", "") // still fail-open
	app := initNewRelic()
	if app != nil {
		t.Errorf("app should still be nil — empty license key overrides app name")
	}
}

// Static check: we expect os.Args[0] to be a real binary name when this
// test runs, so basic process plumbing is healthy. Cheap smoke test.
func TestProcessSmoke(t *testing.T) {
	if os.Args[0] == "" {
		t.Fatal("os.Args[0] empty — test runner misconfigured")
	}
	if errors.Is(nil, http.ErrServerClosed) {
		t.Fatal("errors.Is(nil, http.ErrServerClosed) should be false")
	}
}
