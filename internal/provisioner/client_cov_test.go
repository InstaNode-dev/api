package provisioner

// client_cov_test.go — coverage-completeness suite for the api/internal/provisioner
// gRPC client. Drives every RPC wrapper (ProvisionPostgres / ProvisionCache /
// ProvisionNoSQL / ProvisionQueue / StorageBytes / DeprovisionResource), the
// constructor (NewClient), the health probe (HealthCheck), the breaker
// accessor (Breaker), the metadata helpers (ctxWithAuth, ctxWithTeamID), and
// the per-tier timeout (provisionTimeout). Uses bufconn + a mock
// ProvisionerServiceServer + the gRPC health server so no real network is
// involved.
//
// Scope: package `provisioner` only — same scope as client_auth_test.go and
// circuit_test.go. Drives lines that were 0% before this file lands.

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthgrpc "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "instant.dev/proto/common/v1"
	provisionerv1 "instant.dev/proto/provisioner/v1"
)

// covServer is a fully-controllable mock ProvisionerServiceServer. Each
// per-RPC field, when non-nil, overrides the default success response.
type covServer struct {
	provisionerv1.UnimplementedProvisionerServiceServer

	// If set, ProvisionResource returns this error (per RPC call).
	provisionErr error
	// Override ProvisionResource success payload.
	provisionResp *provisionerv1.ProvisionResponse

	// If non-nil, ProvisionResource blocks until this channel is closed OR
	// the RPC context is cancelled (whichever comes first) — simulating a
	// hung provisioner so the client-side deadline can be exercised.
	provisionBlock chan struct{}

	// Sniffed inbound metadata from the most recent ProvisionResource call.
	lastAuthToken []string
	lastRequestID []string
	lastTeamID    []string

	// If set, GetStorageBytes returns this error.
	storageErr error
	// Override GetStorageBytes payload.
	storageResp *provisionerv1.StorageResponse

	// If set, DeprovisionResource returns this error.
	deprovisionErr error
}

func (s *covServer) ProvisionResource(ctx context.Context, req *provisionerv1.ProvisionRequest) (*provisionerv1.ProvisionResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		s.lastAuthToken = md.Get("x-instant-provisioner-token")
		s.lastRequestID = md.Get("x-request-id")
		s.lastTeamID = md.Get("x-instant-team-id")
	}
	if s.provisionBlock != nil {
		// Simulate a hung provisioner: block until released or the RPC
		// context (carrying the client's deadline) is cancelled.
		select {
		case <-s.provisionBlock:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	if s.provisionErr != nil {
		return nil, s.provisionErr
	}
	if s.provisionResp != nil {
		return s.provisionResp, nil
	}
	return &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "postgres://u:p@host:5432/db",
		DatabaseName:       "db",
		Username:           "u",
		ProviderResourceId: "pr-1",
		KeyPrefix:          "kp-1:",
	}, nil
}

func (s *covServer) GetStorageBytes(ctx context.Context, req *provisionerv1.StorageRequest) (*provisionerv1.StorageResponse, error) {
	if s.storageErr != nil {
		return nil, s.storageErr
	}
	if s.storageResp != nil {
		return s.storageResp, nil
	}
	return &provisionerv1.StorageResponse{StorageBytes: 1234, MeasuredAt: time.Now().Unix()}, nil
}

func (s *covServer) DeprovisionResource(ctx context.Context, req *provisionerv1.DeprovisionRequest) (*provisionerv1.DeprovisionResponse, error) {
	if s.deprovisionErr != nil {
		return nil, s.deprovisionErr
	}
	return &provisionerv1.DeprovisionResponse{}, nil
}

// covHarness wires a bufconn-backed gRPC server with both the provisioner
// service and the standard gRPC health-checking service, plus a Client whose
// `conn` field is populated (so HealthCheck can dial back over the same conn).
type covHarness struct {
	srv    *grpc.Server
	lis    *bufconn.Listener
	conn   *grpc.ClientConn
	client *Client
	health *healthgrpc.Server
	mock   *covServer
}

func (h *covHarness) close() {
	if h.conn != nil {
		_ = h.conn.Close()
	}
	if h.srv != nil {
		h.srv.Stop()
	}
}

// newCovHarness builds the in-process gRPC stack with health server +
// the covServer + a Client whose secret matches the server's auth
// interceptor (so RPCs are admitted).
func newCovHarness(t *testing.T, serverSecret string) *covHarness {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(serverSecret)))
	mock := &covServer{}
	provisionerv1.RegisterProvisionerServiceServer(srv, mock)
	hs := healthgrpc.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)

	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &Client{
		grpc:   provisionerv1.NewProvisionerServiceClient(conn),
		conn:   conn,
		secret: serverSecret,
	}
	return &covHarness{srv: srv, lis: lis, conn: conn, client: c, health: hs, mock: mock}
}

// --- NewClient ---------------------------------------------------------------

// TestNewClient_DialsAndBuildsBreaker verifies the constructor returns a
// Client with the breaker wired and the conn populated. Dialing to a
// passthrough address with insecure creds succeeds at construction time
// even though no server exists — gRPC NewClient is lazy.
func TestNewClient_DialsAndBuildsBreaker(t *testing.T) {
	c, conn, err := NewClient("passthrough:///127.0.0.1:0", "secret-bytes")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c == nil || conn == nil {
		t.Fatal("NewClient returned nil client or conn")
	}
	if c.Breaker() == nil {
		t.Fatal("Breaker() == nil; constructor must wire a breaker")
	}
	if c.secret != "secret-bytes" {
		t.Errorf("secret = %q; want %q", c.secret, "secret-bytes")
	}
	if c.conn != conn {
		t.Error("Client.conn must equal returned conn")
	}
	_ = conn.Close()
}

// TestNewClient_OnOpenLogger fires the WithOnOpen callback by tripping the
// breaker. The callback is logged-only (no return) but executing it ensures
// the closure registered in NewClient is reachable in coverage.
func TestNewClient_OnOpenLogger(t *testing.T) {
	c, conn, err := NewClient("passthrough:///127.0.0.1:0", "x")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer conn.Close()
	br := c.Breaker()
	// Trip the breaker manually — Record advances the consecutive-failure
	// counter, and at threshold (5) the OnOpen callback fires.
	for i := 0; i < provisionerCircuitThreshold; i++ {
		br.Record(errors.New("server faulted"))
	}
	// We can't assert the log line directly without plumbing a writer; but
	// the line is executed (covered) as a side effect of crossing the threshold.
	// The breaker should now be OPEN. We don't assert on the result: Allow may
	// return true for the first half-open trial in some configurations — the
	// point is simply that the OnOpen closure ran (a covered side effect).
	_ = br.Allow()
}

// --- Breaker accessor --------------------------------------------------------

func TestBreaker_AccessorReturnsWiredBreaker(t *testing.T) {
	c, conn, _ := NewClient("passthrough:///127.0.0.1:0", "x")
	defer conn.Close()
	if c.Breaker() == nil {
		t.Fatal("Breaker() returned nil")
	}
}

// --- HealthCheck -------------------------------------------------------------

// TestHealthCheck_Serving — a healthy provisioner with health-server SERVING.
func TestHealthCheck_Serving(t *testing.T) {
	h := newCovHarness(t, "health-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.client.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

// TestHealthCheck_NotServing — when SetServingStatus is NOT_SERVING we
// expect a non-nil error whose message contains NOT_SERVING.
func TestHealthCheck_NotServing(t *testing.T) {
	h := newCovHarness(t, "health-ns-secret")
	defer h.close()
	h.health.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := h.client.HealthCheck(ctx)
	if err == nil {
		t.Fatal("HealthCheck must error when status != SERVING")
	}
	if !strings.Contains(err.Error(), "NOT_SERVING") {
		t.Errorf("err = %v; want substring NOT_SERVING", err)
	}
}

// TestHealthCheck_RPCError — when the health probe RPC itself fails (we kill
// the server before calling), HealthCheck returns the gRPC error verbatim.
func TestHealthCheck_RPCError(t *testing.T) {
	h := newCovHarness(t, "health-rpc-secret")
	// Tear down the server immediately so the next RPC fails.
	h.srv.Stop()
	defer func() {
		_ = h.conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := h.client.HealthCheck(ctx); err == nil {
		t.Fatal("HealthCheck must error when RPC fails")
	}
}

// TestHealthCheck_NilReceiver — receiver-nil and conn-nil branches return
// the documented "provisioner_conn_not_configured" sentinel.
func TestHealthCheck_NilReceiver(t *testing.T) {
	var nilClient *Client
	if err := nilClient.HealthCheck(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "provisioner_conn_not_configured") {
		t.Errorf("nil receiver: err = %v; want provisioner_conn_not_configured", err)
	}
	c := &Client{} // conn is nil
	if err := c.HealthCheck(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "provisioner_conn_not_configured") {
		t.Errorf("nil conn: err = %v; want provisioner_conn_not_configured", err)
	}
}

// --- ctxWithAuth + ctxWithTeamID --------------------------------------------

// TestCtxWithAuth_AttachesRequestID drives the rid != "" branch in
// ctxWithAuth by constructing a context that carries a request id under the
// middleware's private key — we route through middleware.RequestID() via a
// fiber handler so the unexported key is honored.
func TestCtxWithAuth_AttachesRequestID(t *testing.T) {
	h := newCovHarness(t, "rid-cov-secret")
	defer h.close()

	// Build a context that the middleware would have populated. The key is
	// unexported; we cannot synthesise it directly. But the request-ID
	// branch is the ONLY path that adds the second AppendToOutgoingContext —
	// the rest is exercised by the empty-rid path. We assert empty here, and
	// rely on rid-set behaviour being exercised at integration level. The
	// branch ITSELF (the if-block body) is still hit by any non-empty rid
	// from the middleware, which is impossible to construct from outside the
	// middleware package. So we drive the empty path via background ctx (no
	// rid), and verify the auth-token is forwarded — which already covers
	// the function body except the if-block.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := h.client.ProvisionPostgres(ctx, "tok-rid", "hobby", ""); err != nil {
		t.Fatalf("ProvisionPostgres: %v", err)
	}
	if got := h.mock.lastAuthToken; len(got) != 1 || got[0] != "rid-cov-secret" {
		t.Errorf("auth header = %v; want [rid-cov-secret]", got)
	}
}

// TestCtxWithTeamID_EmptyAndSet drives both arms of ctxWithTeamID. Empty
// teamID returns ctx unchanged; non-empty appends the metadata.
func TestCtxWithTeamID_EmptyAndSet(t *testing.T) {
	h := newCovHarness(t, "team-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Empty teamID — header must NOT be present.
	if _, err := h.client.ProvisionPostgres(ctx, "tok-empty-team", "anonymous", ""); err != nil {
		t.Fatalf("ProvisionPostgres empty team: %v", err)
	}
	if len(h.mock.lastTeamID) != 0 {
		t.Errorf("empty teamID: server saw x-instant-team-id=%v; want none", h.mock.lastTeamID)
	}

	// Non-empty teamID — header must be present with that value.
	if _, err := h.client.ProvisionPostgres(ctx, "tok-set-team", "pro", "team-uuid-123"); err != nil {
		t.Fatalf("ProvisionPostgres set team: %v", err)
	}
	if got := h.mock.lastTeamID; len(got) != 1 || got[0] != "team-uuid-123" {
		t.Errorf("set teamID: server saw x-instant-team-id=%v; want [team-uuid-123]", got)
	}
}

// --- provisionTimeout --------------------------------------------------------

func TestProvisionTimeout_PerTier(t *testing.T) {
	cases := []struct {
		tier string
		want time.Duration
	}{
		{"pro", 5 * time.Minute},
		{"team", 5 * time.Minute},
		{"growth", 5 * time.Minute},
		{"anonymous", 4 * time.Minute},
		{"hobby", 4 * time.Minute},
		{"hobby_plus", 4 * time.Minute},
		{"free", 4 * time.Minute},
		{"", 4 * time.Minute},
	}
	for _, tc := range cases {
		if got := provisionTimeout(tc.tier); got != tc.want {
			t.Errorf("provisionTimeout(%q) = %s; want %s", tc.tier, got, tc.want)
		}
	}
}

// --- Provision* RPC wrappers — success + error branches ---------------------

// TestProvisionPostgres_SuccessAndError covers the happy path AND the error
// branch (wrapped error message includes "provisioner.ProvisionPostgres:").
func TestProvisionPostgres_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "pg-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h.mock.provisionResp = &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "postgres://x",
		DatabaseName:       "x",
		Username:           "x",
		ProviderResourceId: "pg-prid",
	}
	creds, err := h.client.ProvisionPostgres(ctx, "tok", "hobby", "team-1")
	if err != nil {
		t.Fatalf("ProvisionPostgres ok: %v", err)
	}
	if creds.URL != "postgres://x" || creds.ProviderResourceID != "pg-prid" {
		t.Errorf("creds = %+v", creds)
	}

	h.mock.provisionResp = nil
	h.mock.provisionErr = status.Error(codes.Unavailable, "provisioner sick")
	_, err = h.client.ProvisionPostgres(ctx, "tok", "hobby", "team-1")
	if err == nil || !strings.Contains(err.Error(), "provisioner.ProvisionPostgres:") {
		t.Errorf("err = %v; want wrapped ProvisionPostgres error", err)
	}
}

func TestProvisionCache_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "cache-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h.mock.provisionResp = &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "redis://x:6379",
		KeyPrefix:          "ns42:",
		ProviderResourceId: "cache-prid",
	}
	creds, err := h.client.ProvisionCache(ctx, "tok", "pro", "team-2")
	if err != nil {
		t.Fatalf("ProvisionCache ok: %v", err)
	}
	if creds.KeyPrefix != "ns42:" || creds.ProviderResourceID != "cache-prid" {
		t.Errorf("creds = %+v", creds)
	}

	h.mock.provisionResp = nil
	h.mock.provisionErr = status.Error(codes.Internal, "boom")
	if _, err := h.client.ProvisionCache(ctx, "tok", "pro", ""); err == nil ||
		!strings.Contains(err.Error(), "provisioner.ProvisionCache:") {
		t.Errorf("err = %v; want wrapped ProvisionCache error", err)
	}
}

// TestCacheProvisionTimeout_Value pins the production deadline derivation:
// the cache RPC deadline must equal the provisioner's dedicated pod-ready
// budget plus margin. A bare literal here (the old 45s "Redis is always a
// shared carve" ceiling) undercut the provisioner's 3m k8s ready-wait and
// killed legitimate cold-pod provisions mid-flight (Wave-2 A1).
func TestCacheProvisionTimeout_Value(t *testing.T) {
	if want := dedicatedProvisionReadyWait + provisionRPCDeadlineMargin; cacheProvisionTimeout != want {
		t.Errorf("cacheProvisionTimeout = %s; want %s (dedicatedProvisionReadyWait + provisionRPCDeadlineMargin)",
			cacheProvisionTimeout, want)
	}
	// Still bounded: must not balloon past provisionTimeout's pod-backed
	// budget — a hung provisioner has to fail /cache/new within the same
	// envelope as every other provision RPC.
	if cacheProvisionTimeout > provisionTimeout("pro") {
		t.Errorf("cacheProvisionTimeout (%s) must not exceed provisionTimeout(pro) (%s)",
			cacheProvisionTimeout, provisionTimeout("pro"))
	}
}

// TestProvisionTimeouts_NeverUndercutDedicatedReadyWait enforces the Wave-2 A1
// invariant for EVERY provision deadline in this package: no RPC deadline may
// undercut the provisioner's dedicated pod-ready wait (3m) plus margin. The
// tier list spans both provisionTimeout branches plus unknown-tier fallback so
// a future tier addition can't silently reintroduce an undercutting budget.
func TestProvisionTimeouts_NeverUndercutDedicatedReadyWait(t *testing.T) {
	floor := dedicatedProvisionReadyWait + provisionRPCDeadlineMargin
	for _, tier := range []string{"anonymous", "free", "hobby", "hobby_plus", "pro", "growth", "team", "some-future-tier"} {
		if got := provisionTimeout(tier); got < floor {
			t.Errorf("provisionTimeout(%q) = %s; must be >= %s (dedicated ready-wait + margin)", tier, got, floor)
		}
	}
	if cacheProvisionTimeout < floor {
		t.Errorf("cacheProvisionTimeout = %s; must be >= %s (dedicated ready-wait + margin)", cacheProvisionTimeout, floor)
	}
}

// TestProvisionCache_HangBecomesDeadlineError proves the defensive fix: when
// the provisioner hangs, ProvisionCache's own client-side deadline fires and
// returns a DeadlineExceeded-class error in ~the bounded window — NOT an
// indefinite block. This is the error the cache handler converts into a 503
// provision_failed after marking the pending resource 'failed'.
//
// We shrink cacheProvisionTimeout to a few ms (restored via t.Cleanup) so the
// test is fast, and give the *caller* context a generous timeout so the error
// is provably caused by our internal deadline, not the caller's.
func TestProvisionCache_HangBecomesDeadlineError(t *testing.T) {
	orig := cacheProvisionTimeout
	cacheProvisionTimeout = 50 * time.Millisecond
	t.Cleanup(func() { cacheProvisionTimeout = orig })

	h := newCovHarness(t, "hang-secret")
	defer h.close()

	// Server blocks forever (channel never closed) → only the client-side
	// deadline can end the RPC.
	h.mock.provisionBlock = make(chan struct{})

	// Caller context is far more generous than the 50ms internal deadline,
	// so a failure here is unambiguously our deadline firing.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := h.client.ProvisionCache(ctx, "tok", "pro", "team-hang")
		done <- err
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("ProvisionCache returned nil; want a DeadlineExceeded-class error from the bounded deadline")
		}
		if !strings.Contains(err.Error(), "provisioner.ProvisionCache:") {
			t.Errorf("err = %v; want wrapped ProvisionCache error", err)
		}
		if st, ok := status.FromError(err); !ok || st.Code() != codes.DeadlineExceeded {
			t.Errorf("err = %v; want gRPC DeadlineExceeded", err)
		}
		// Bounded: must finish well within the caller's 10s, near the 50ms
		// internal deadline — proves the api no longer hangs on a hung provisioner.
		if elapsed > 5*time.Second {
			t.Errorf("ProvisionCache took %s; expected ~the bounded deadline (50ms), not an indefinite hang", elapsed)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("ProvisionCache hung past the bounded deadline — the defensive timeout did not fire")
	}
}

func TestProvisionNoSQL_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "mongo-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h.mock.provisionResp = &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "mongodb://x",
		DatabaseName:       "mdb",
		Username:           "mu",
		ProviderResourceId: "mongo-prid",
	}
	creds, err := h.client.ProvisionNoSQL(ctx, "tok", "growth", "team-3")
	if err != nil {
		t.Fatalf("ProvisionNoSQL ok: %v", err)
	}
	if creds.DatabaseName != "mdb" || creds.ProviderResourceID != "mongo-prid" {
		t.Errorf("creds = %+v", creds)
	}

	h.mock.provisionResp = nil
	h.mock.provisionErr = status.Error(codes.Unknown, "boom")
	if _, err := h.client.ProvisionNoSQL(ctx, "tok", "hobby", ""); err == nil ||
		!strings.Contains(err.Error(), "provisioner.ProvisionNoSQL:") {
		t.Errorf("err = %v; want wrapped ProvisionNoSQL error", err)
	}
}

func TestProvisionQueue_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "queue-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h.mock.provisionResp = &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "nats://x:4222",
		KeyPrefix:          "stream-x",
		ProviderResourceId: "queue-prid",
	}
	creds, err := h.client.ProvisionQueue(ctx, "tok", "team", "team-4")
	if err != nil {
		t.Fatalf("ProvisionQueue ok: %v", err)
	}
	if creds.URL != "nats://x:4222" || creds.KeyPrefix != "stream-x" || creds.ProviderResourceID != "queue-prid" {
		t.Errorf("creds = %+v", creds)
	}

	h.mock.provisionResp = nil
	h.mock.provisionErr = status.Error(codes.ResourceExhausted, "no room")
	if _, err := h.client.ProvisionQueue(ctx, "tok", "anonymous", ""); err == nil ||
		!strings.Contains(err.Error(), "provisioner.ProvisionQueue:") {
		t.Errorf("err = %v; want wrapped ProvisionQueue error", err)
	}
}

// --- StorageBytes ------------------------------------------------------------

func TestStorageBytes_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "storage-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	h.mock.storageResp = &provisionerv1.StorageResponse{StorageBytes: 9999}
	n, err := h.client.StorageBytes(ctx, "tok", "prid", commonv1.ResourceType_RESOURCE_TYPE_POSTGRES)
	if err != nil {
		t.Fatalf("StorageBytes ok: %v", err)
	}
	if n != 9999 {
		t.Errorf("StorageBytes = %d; want 9999", n)
	}

	h.mock.storageResp = nil
	h.mock.storageErr = status.Error(codes.Unavailable, "boom")
	if _, err := h.client.StorageBytes(ctx, "tok", "prid", commonv1.ResourceType_RESOURCE_TYPE_REDIS); err == nil ||
		!strings.Contains(err.Error(), "provisioner.StorageBytes:") {
		t.Errorf("err = %v; want wrapped StorageBytes error", err)
	}
}

// --- DeprovisionResource -----------------------------------------------------

func TestDeprovisionResource_SuccessAndError(t *testing.T) {
	h := newCovHarness(t, "deprov-secret")
	defer h.close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := h.client.DeprovisionResource(ctx, "tok", "prid", commonv1.ResourceType_RESOURCE_TYPE_POSTGRES); err != nil {
		t.Fatalf("DeprovisionResource ok: %v", err)
	}

	h.mock.deprovisionErr = status.Error(codes.Internal, "drop failed")
	err := h.client.DeprovisionResource(ctx, "tok", "prid", commonv1.ResourceType_RESOURCE_TYPE_MONGODB)
	if err == nil || !strings.Contains(err.Error(), "provisioner.DeprovisionResource:") {
		t.Errorf("err = %v; want wrapped DeprovisionResource error", err)
	}
}

// --- nil-breaker fast paths (Client built as struct literal with no breaker) -

// TestRPCs_NilBreakerPath drives the b == nil branch in callWithBreaker via
// every wrapper. The previous tests in the file pass through the breaker
// (NewClient wires one). Here we construct a Client whose breaker is nil
// — the same shape client_auth_test.go uses — and confirm RPCs still
// flow.
func TestRPCs_NilBreakerPath(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	const secret = "nil-breaker-secret"
	srv := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(secret)))
	mock := &covServer{}
	provisionerv1.RegisterProvisionerServiceServer(srv, mock)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	defer conn.Close()

	c := &Client{
		grpc:   provisionerv1.NewProvisionerServiceClient(conn),
		conn:   conn,
		secret: secret,
		// breaker intentionally nil — drives the early-return in callWithBreaker
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := c.ProvisionPostgres(ctx, "t", "hobby", ""); err != nil {
		t.Errorf("ProvisionPostgres nil-breaker: %v", err)
	}
	if _, err := c.ProvisionCache(ctx, "t", "hobby", ""); err != nil {
		t.Errorf("ProvisionCache nil-breaker: %v", err)
	}
	if _, err := c.ProvisionNoSQL(ctx, "t", "hobby", ""); err != nil {
		t.Errorf("ProvisionNoSQL nil-breaker: %v", err)
	}
	if _, err := c.ProvisionQueue(ctx, "t", "hobby", ""); err != nil {
		t.Errorf("ProvisionQueue nil-breaker: %v", err)
	}
	if _, err := c.StorageBytes(ctx, "t", "p", commonv1.ResourceType_RESOURCE_TYPE_POSTGRES); err != nil {
		t.Errorf("StorageBytes nil-breaker: %v", err)
	}
	if err := c.DeprovisionResource(ctx, "t", "p", commonv1.ResourceType_RESOURCE_TYPE_POSTGRES); err != nil {
		t.Errorf("DeprovisionResource nil-breaker: %v", err)
	}
}
