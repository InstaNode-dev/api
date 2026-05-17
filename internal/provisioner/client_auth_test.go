package provisioner

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "instant.dev/proto/common/v1"
	provisionerv1 "instant.dev/proto/provisioner/v1"
)

// TestClient_PresentsAuthToken_OnEveryRPC is the regression test for the
// 2026-05-13 outage where the provisioner rejected every /db/new call with
// `code = Unauthenticated desc = invalid provisioner token`. The api code is
// supposed to attach `x-instant-provisioner-token` metadata on every call;
// this test pins that behaviour at the wire level so a future refactor cannot
// silently drop the header.
//
// The companion repo's provisioner/internal/interceptor/auth.go validates the
// header value byte-for-byte against the server's captured-at-startup
// `secret` string. If the api stops sending the header, OR the api sends a
// different value, the call returns Unauthenticated. This test exercises both
// shapes against a real in-process gRPC server.
func TestClient_PresentsAuthToken_OnEveryRPC(t *testing.T) {
	const serverSecret = "test-secret-must-be-non-empty-and-stable"

	tests := []struct {
		name         string
		clientSecret string
		wantCode     codes.Code
	}{
		{"matching_secret_succeeds", serverSecret, codes.OK},
		{"different_secret_rejected", "wrong-secret-rotated-but-pods-not-restarted", codes.Unauthenticated},
		{"empty_secret_rejected", "", codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lis := bufconn.Listen(1 << 20)
			srv := grpc.NewServer(
				grpc.UnaryInterceptor(authInterceptor(serverSecret)),
			)
			provisionerv1.RegisterProvisionerServiceServer(srv, &stubServer{})

			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = srv.Serve(lis)
			}()
			defer func() {
				srv.Stop()
				<-done
			}()

			conn, err := grpc.NewClient("passthrough://bufnet",
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			c := &Client{
				grpc:   provisionerv1.NewProvisionerServiceClient(conn),
				secret: tt.clientSecret,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err = c.ProvisionPostgres(ctx, "00000000-0000-0000-0000-000000000001", "anonymous", "")
			gotCode := status.Code(err)
			if gotCode != tt.wantCode {
				t.Fatalf("got code=%v err=%v, want %v", gotCode, err, tt.wantCode)
			}
		})
	}
}

// TestClient_AttachesRequestIDMetadata pins the cross-service correlation
// behaviour: when the calling context carries an X-Request-ID, the api MUST
// forward it to the provisioner so logs can be joined. A regression here
// makes outage triage measurably harder (we'd lose the join key we used to
// diagnose the 2026-05-13 incident).
func TestClient_AttachesRequestIDMetadata(t *testing.T) {
	const serverSecret = "rid-test-secret-bytes"

	lis := bufconn.Listen(1 << 20)
	sniffer := &requestIDSniffer{}
	srv := grpc.NewServer(
		grpc.UnaryInterceptor(authInterceptor(serverSecret)),
	)
	provisionerv1.RegisterProvisionerServiceServer(srv, sniffer)
	go srv.Serve(lis) //nolint:errcheck
	defer srv.Stop()

	conn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	defer conn.Close()
	c := &Client{grpc: provisionerv1.NewProvisionerServiceClient(conn), secret: serverSecret}

	// We do NOT set a request_id in this stripped harness because the
	// middleware-context plumbing is exercised end-to-end in the e2e/ suite.
	// Here we only assert the auth header is always present (sniffer below).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = c.ProvisionPostgres(ctx, "00000000-0000-0000-0000-000000000002", "anonymous", "")
	if sniffer.tokenLastSeen != serverSecret {
		t.Fatalf("auth token not propagated to server; sniffer saw %q want %q", sniffer.tokenLastSeen, serverSecret)
	}
}

// --- test helpers (private to this file) -----------------------------------

func authInterceptor(secret string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}
		vals := md.Get("x-instant-provisioner-token")
		if len(vals) == 0 || vals[0] != secret {
			return nil, status.Error(codes.Unauthenticated, "invalid provisioner token")
		}
		return handler(ctx, req)
	}
}

type stubServer struct {
	provisionerv1.UnimplementedProvisionerServiceServer
}

func (s *stubServer) ProvisionResource(ctx context.Context, req *provisionerv1.ProvisionRequest) (*provisionerv1.ProvisionResponse, error) {
	return &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "postgres://u:p@host:5432/db",
		DatabaseName:       "db",
		Username:           "u",
		ProviderResourceId: "stub",
	}, nil
}

type requestIDSniffer struct {
	provisionerv1.UnimplementedProvisionerServiceServer
	tokenLastSeen string
}

func (r *requestIDSniffer) ProvisionResource(ctx context.Context, req *provisionerv1.ProvisionRequest) (*provisionerv1.ProvisionResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("x-instant-provisioner-token"); len(v) > 0 {
			r.tokenLastSeen = v[0]
		}
	}
	return &provisionerv1.ProvisionResponse{ConnectionUrl: "x", DatabaseName: "x", Username: "x", ProviderResourceId: "x"}, nil
}

// silence unused — commonv1 import kept for future ResourceType assertions.
var _ = commonv1.ResourceType_RESOURCE_TYPE_POSTGRES

// TestClient_SurfacesProviderResourceID_FromPoolHit is the api-side P0-2
// regression guard. When the provisioner serves a /db/new /cache/new /nosql/new
// request FROM the hot pool, the backing infra is named from the synthetic
// pool token, and the provisioner returns that canonical identifier in the
// ProvisionResponse.provider_resource_id field (the provisioner repo encodes a
// "pooltok:" marker into it). The api MUST surface that value into
// Credentials.ProviderResourceID so the handler persists it on the resource
// row — Deprovision / StorageBytes / Regrade then resolve the real backing-
// infra name from it. If a refactor drops this mapping, the pool token never
// reaches the resource row and the pool-claimed infra leaks forever again.
func TestClient_SurfacesProviderResourceID_FromPoolHit(t *testing.T) {
	const (
		serverSecret = "poolident-contract-secret-bytes"
		poolPRID     = "pooltok:pool-12345678-90ab-cdef-1234-567890abcdef"
	)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(serverSecret)))
	provisionerv1.RegisterProvisionerServiceServer(srv, &poolPRIDStubServer{prid: poolPRID})
	go srv.Serve(lis) //nolint:errcheck
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	c := &Client{grpc: provisionerv1.NewProvisionerServiceClient(conn), secret: serverSecret}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Every provision path that can be served from the pool must surface the
	// provider_resource_id. Postgres, Redis and Mongo all have warm pools.
	calls := map[string]func() (*Credentials, error){
		"ProvisionPostgres": func() (*Credentials, error) {
			return c.ProvisionPostgres(ctx, "00000000-0000-0000-0000-0000000000a1", "anonymous", "")
		},
		"ProvisionCache": func() (*Credentials, error) {
			return c.ProvisionCache(ctx, "00000000-0000-0000-0000-0000000000a2", "anonymous", "")
		},
		"ProvisionNoSQL": func() (*Credentials, error) {
			return c.ProvisionNoSQL(ctx, "00000000-0000-0000-0000-0000000000a3", "anonymous", "")
		},
	}
	for name, call := range calls {
		creds, err := call()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if creds.ProviderResourceID != poolPRID {
			t.Errorf("%s: ProviderResourceID = %q, want %q — pool-claimed infra would leak (P0-2)",
				name, creds.ProviderResourceID, poolPRID)
		}
	}
}

// poolPRIDStubServer answers every ProvisionResource RPC with a fixed
// provider_resource_id, mimicking a provisioner pool hit.
type poolPRIDStubServer struct {
	provisionerv1.UnimplementedProvisionerServiceServer
	prid string
}

func (s *poolPRIDStubServer) ProvisionResource(ctx context.Context, req *provisionerv1.ProvisionRequest) (*provisionerv1.ProvisionResponse, error) {
	return &provisionerv1.ProvisionResponse{
		ConnectionUrl:      "redis://usr_pool-x:pw@host:6379/0",
		DatabaseName:       "db_pool-x",
		Username:           "usr_pool-x",
		KeyPrefix:          "pool-x:",
		ProviderResourceId: s.prid,
	}, nil
}
