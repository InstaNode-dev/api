package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"instant.dev/internal/circuit"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	commonv1 "instant.dev/proto/common/v1"
	provisionerv1 "instant.dev/proto/provisioner/v1"
)

// Circuit-breaker tuning for the api → provisioner gRPC boundary.
// See README in internal/circuit for the state machine. Constants are
// package-private (not env-tunable) because a misconfigured breaker is
// worse than no breaker — operators who want to disable it can deploy
// without the wrapped Client.
const (
	provisionerCircuitName      = "provisioner"
	provisionerCircuitThreshold = 5
	provisionerCircuitCooldown  = 30 * time.Second
)

// Credentials matches the shape returned by local providers.
type Credentials struct {
	URL                string
	DatabaseName       string
	Username           string
	ProviderResourceID string
	KeyPrefix          string
}

// Client wraps the gRPC ProvisionerServiceClient with convenience methods
// and a process-shared circuit breaker.
type Client struct {
	grpc    provisionerv1.ProvisionerServiceClient
	secret  string
	breaker *circuit.Breaker // nil-safe; tests that construct {grpc, secret} still work
}

// NewClient dials the provisioner gRPC server and returns a Client.
// The caller is responsible for calling conn.Close() on shutdown.
//
// The Client is constructed with a shared circuit breaker named
// "provisioner" that trips on 5 consecutive RPC errors and stays open
// for 30s. Inspect via `instant_circuit_breaker_state{name="provisioner"}`.
func NewClient(addr, secret string) (*Client, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()), // mTLS added in production via env
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("provisioner.NewClient: %w", err)
	}
	br := circuit.NewBreaker(
		provisionerCircuitName,
		provisionerCircuitThreshold,
		provisionerCircuitCooldown,
	).WithOnOpen(func() {
		slog.Error("provisioner.circuit.opened",
			"name", provisionerCircuitName,
			"threshold", provisionerCircuitThreshold,
			"cooldown_seconds", int(provisionerCircuitCooldown.Seconds()),
			"impact", "all /db/new /cache/new /nosql/new /queue/new will 503 until provisioner recovers",
			"runbook", "https://instanode.dev/status",
		)
	})
	return &Client{
		grpc:    provisionerv1.NewProvisionerServiceClient(conn),
		secret:  secret,
		breaker: br,
	}, conn, nil
}

// callWithBreaker wraps a single RPC under the shared breaker. Returns
// circuit.ErrOpen WITHOUT issuing the RPC when the breaker is open.
// A nil breaker is treated as closed (test paths that build the Client
// as a struct literal don't need the breaker wired).
//
// P1-1 (CIRCUIT-RETRY-AUDIT 2026-05-20): not every non-nil error indicates
// a *server* fault. Caller-side cancellations and bad-input gRPC codes are
// scrubbed via shouldRecordBreakerErr before reaching Record, so a flood of
// abandoned clients or malformed requests can no longer trip the breaker
// for EVERYONE — preventing a self-inflicted /db/new outage caused by one
// misbehaving caller. nil and "real" upstream errors still flow through
// Record unchanged, so a genuine provisioner outage still trips the breaker
// at the documented threshold.
func callWithBreaker[T any](b *circuit.Breaker, fn func() (T, error)) (T, error) {
	if b == nil {
		return fn()
	}
	var zero T
	if !b.Allow() {
		return zero, circuit.ErrOpen
	}
	out, err := fn()
	if shouldRecordBreakerErr(err) {
		b.Record(err)
	} else {
		// We consumed an Allow() slot — for half-open trial fairness we
		// must still tell the breaker "this call did not fail" so a
		// successful trial closes and the half-open slot is released.
		// Recording a nil here is the documented success path.
		b.Record(nil)
	}
	return out, err
}

// shouldRecordBreakerErr reports whether err represents a real provisioner
// fault (Unavailable, ResourceExhausted, server-side DeadlineExceeded,
// Internal, Unknown, etc.) and should therefore advance the consecutive-
// failure counter, OR a caller/argument problem (context.Canceled,
// context.DeadlineExceeded from the *caller's* abandoned ctx, gRPC
// InvalidArgument / FailedPrecondition / PermissionDenied / Unauthenticated
// / NotFound) that must NOT count toward tripping.
//
// Two reference points for the policy:
//
//   - https://grpc.io/docs/guides/error/ — only "service is unavailable"
//     class errors should drive caller-side circuit logic.
//   - gRPC's own Wait-For-Ready semantics treat Unavailable distinctly.
//
// Returns true for "record as failure", false for "scrub" (treated as a
// successful trial by the caller, since the inner fn returned but the
// failure is the *caller's* fault not the server's).
//
// nil errs are NEVER passed here — they are recorded as success by Record
// in the regular path. shouldRecordBreakerErr is only consulted for non-nil.
func shouldRecordBreakerErr(err error) bool {
	if err == nil {
		// Defensive — Record(nil) is success; callers don't need to ask.
		return true
	}
	// Caller-cancelled context. The user closed the browser tab, the
	// upstream HTTP request timed out, etc. — provisioner side never
	// saw a problem, so don't punish it.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// gRPC status codes that signal "the request is bad", not "the server
	// is sick". A flood of these from one misbehaving caller MUST NOT trip
	// the breaker for everyone else.
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Canceled,
			codes.InvalidArgument,
			codes.FailedPrecondition,
			codes.PermissionDenied,
			codes.Unauthenticated,
			codes.NotFound,
			codes.AlreadyExists,
			codes.OutOfRange:
			return false
		}
	}
	return true
}

// Breaker exposes the underlying breaker for tests and /healthz.
func (c *Client) Breaker() *circuit.Breaker { return c.breaker }

// ctxWithAuth attaches the provisioner auth token and, if present, the
// X-Request-ID from the calling HTTP request so the provisioner's logs
// can be correlated back to the originating API request.
func (c *Client) ctxWithAuth(ctx context.Context) context.Context {
	ctx = metadata.AppendToOutgoingContext(ctx, "x-instant-provisioner-token", c.secret)
	if rid := middleware.RequestIDFromContext(ctx); rid != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-request-id", rid)
	}
	return ctx
}

// provisionTimeout returns the gRPC timeout for a provisioning call.
// Every tier now provisions a dedicated k8s pod (since the dedicated-infra-for-
// every-tier change). PVC bind + image pull + postgres init can take 30-90s on
// a cold node, so 10s (the old anonymous default) drops the connection while
// the pod is still coming up. Anonymous gets a tight 4m budget; pro/team get
// 5m for larger images and bigger PVCs.
func provisionTimeout(tier string) time.Duration {
	if tier == "pro" || tier == "team" || tier == "growth" {
		return 5 * time.Minute
	}
	return 4 * time.Minute
}

// ctxWithTeamID attaches the team ID to outgoing gRPC metadata so the
// provisioner can label dedicated namespaces with instant.dev/owner-team.
// This is separate from ctxWithAuth so callers that do not have a team ID
// (anonymous provisioning) do not need to pass an empty string.
func (c *Client) ctxWithTeamID(ctx context.Context, teamID string) context.Context {
	if teamID == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "x-instant-team-id", teamID)
}

// ProvisionPostgres provisions a new Postgres database. Wrapped by the
// shared circuit breaker — when open, returns circuit.ErrOpen in <1ms
// instead of waiting on the gRPC timeout. Handlers branch on
// errors.Is(err, circuit.ErrOpen).
func (c *Client) ProvisionPostgres(ctx context.Context, token, tier, teamID string) (*Credentials, error) {
	return callWithBreaker(c.breaker, func() (*Credentials, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(c.ctxWithTeamID(c.ctxWithAuth(ctx), teamID), provisionTimeout(tier))
		defer cancel()
		resp, err := c.grpc.ProvisionResource(ctx, &provisionerv1.ProvisionRequest{
			Token:        token,
			Tier:         tier,
			ResourceType: commonv1.ResourceType_RESOURCE_TYPE_POSTGRES,
		})
		status := "ok"
		if err != nil {
			status = "error"
		}
		metrics.GRPCDuration.WithLabelValues("ProvisionPostgres", status).Observe(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("provisioner.ProvisionPostgres: %w", err)
		}
		return &Credentials{
			URL: resp.ConnectionUrl, DatabaseName: resp.DatabaseName,
			Username: resp.Username, ProviderResourceID: resp.ProviderResourceId,
		}, nil
	})
}

// ProvisionCache provisions a new Redis cache. Wrapped by the shared
// circuit breaker (see ProvisionPostgres).
func (c *Client) ProvisionCache(ctx context.Context, token, tier, teamID string) (*Credentials, error) {
	return callWithBreaker(c.breaker, func() (*Credentials, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(c.ctxWithTeamID(c.ctxWithAuth(ctx), teamID), provisionTimeout(tier))
		defer cancel()
		resp, err := c.grpc.ProvisionResource(ctx, &provisionerv1.ProvisionRequest{
			Token:        token,
			Tier:         tier,
			ResourceType: commonv1.ResourceType_RESOURCE_TYPE_REDIS,
		})
		status := "ok"
		if err != nil {
			status = "error"
		}
		metrics.GRPCDuration.WithLabelValues("ProvisionCache", status).Observe(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("provisioner.ProvisionCache: %w", err)
		}
		return &Credentials{
			URL: resp.ConnectionUrl, KeyPrefix: resp.KeyPrefix, ProviderResourceID: resp.ProviderResourceId,
		}, nil
	})
}

// ProvisionNoSQL provisions a new MongoDB database. Wrapped by the
// shared circuit breaker (see ProvisionPostgres).
func (c *Client) ProvisionNoSQL(ctx context.Context, token, tier, teamID string) (*Credentials, error) {
	return callWithBreaker(c.breaker, func() (*Credentials, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(c.ctxWithTeamID(c.ctxWithAuth(ctx), teamID), provisionTimeout(tier))
		defer cancel()
		resp, err := c.grpc.ProvisionResource(ctx, &provisionerv1.ProvisionRequest{
			Token:        token,
			Tier:         tier,
			ResourceType: commonv1.ResourceType_RESOURCE_TYPE_MONGODB,
		})
		status := "ok"
		if err != nil {
			status = "error"
		}
		metrics.GRPCDuration.WithLabelValues("ProvisionNoSQL", status).Observe(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("provisioner.ProvisionNoSQL: %w", err)
		}
		return &Credentials{
			URL: resp.ConnectionUrl, DatabaseName: resp.DatabaseName,
			Username: resp.Username, ProviderResourceID: resp.ProviderResourceId,
		}, nil
	})
}

// ProvisionQueue provisions a new NATS JetStream queue.
// For pro/team tiers this creates a dedicated NATS pod; for others it uses the shared cluster.
// Wrapped by the shared circuit breaker.
func (c *Client) ProvisionQueue(ctx context.Context, token, tier, teamID string) (*Credentials, error) {
	return callWithBreaker(c.breaker, func() (*Credentials, error) {
		start := time.Now()
		ctx, cancel := context.WithTimeout(c.ctxWithTeamID(c.ctxWithAuth(ctx), teamID), provisionTimeout(tier))
		defer cancel()
		resp, err := c.grpc.ProvisionResource(ctx, &provisionerv1.ProvisionRequest{
			Token:        token,
			Tier:         tier,
			ResourceType: commonv1.ResourceType_RESOURCE_TYPE_QUEUE,
		})
		status := "ok"
		if err != nil {
			status = "error"
		}
		metrics.GRPCDuration.WithLabelValues("ProvisionQueue", status).Observe(time.Since(start).Seconds())
		if err != nil {
			return nil, fmt.Errorf("provisioner.ProvisionQueue: %w", err)
		}
		return &Credentials{
			URL: resp.ConnectionUrl, KeyPrefix: resp.KeyPrefix, ProviderResourceID: resp.ProviderResourceId,
		}, nil
	})
}

// StorageBytes fetches current storage usage for a resource. Wrapped
// by the shared breaker.
func (c *Client) StorageBytes(ctx context.Context, token, providerResourceID string, resType commonv1.ResourceType) (int64, error) {
	return callWithBreaker(c.breaker, func() (int64, error) {
		ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), 30*time.Second)
		defer cancel()
		resp, err := c.grpc.GetStorageBytes(ctx, &provisionerv1.StorageRequest{
			Token:              token,
			ProviderResourceId: providerResourceID,
			ResourceType:       resType,
		})
		if err != nil {
			return 0, fmt.Errorf("provisioner.StorageBytes: %w", err)
		}
		return resp.StorageBytes, nil
	})
}

// DeprovisionResource removes a provisioned resource. Wrapped by the
// shared breaker.
func (c *Client) DeprovisionResource(ctx context.Context, token, providerResourceID string, resType commonv1.ResourceType) error {
	_, err := callWithBreaker(c.breaker, func() (struct{}, error) {
		ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), 30*time.Second)
		defer cancel()
		_, err := c.grpc.DeprovisionResource(ctx, &provisionerv1.DeprovisionRequest{
			Token:              token,
			ProviderResourceId: providerResourceID,
			ResourceType:       resType,
		})
		if err != nil {
			slog.Error("provisioner.DeprovisionResource failed", "error", err, "token", token)
			return struct{}{}, fmt.Errorf("provisioner.DeprovisionResource: %w", err)
		}
		return struct{}{}, nil
	})
	return err
}
