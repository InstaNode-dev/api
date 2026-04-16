package provisioner

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
	commonv1 "instant.dev/proto/common/v1"
	provisionerv1 "instant.dev/proto/provisioner/v1"
)

// Credentials matches the shape returned by local providers.
type Credentials struct {
	URL                string
	DatabaseName       string
	Username           string
	ProviderResourceID string
	KeyPrefix          string
}

// Client wraps the gRPC ProvisionerServiceClient with convenience methods.
type Client struct {
	grpc   provisionerv1.ProvisionerServiceClient
	secret string
}

// NewClient dials the provisioner gRPC server and returns a Client.
// The caller is responsible for calling conn.Close() on shutdown.
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
	return &Client{
		grpc:   provisionerv1.NewProvisionerServiceClient(conn),
		secret: secret,
	}, conn, nil
}

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
// Pro and team tiers create a dedicated k8s pod per token; pod startup can take 1-3 minutes.
// All other tiers provision on shared infrastructure in < 1 second.
func provisionTimeout(tier string) time.Duration {
	if tier == "pro" || tier == "team" || tier == "growth" {
		return 5 * time.Minute
	}
	return 10 * time.Second
}

// ProvisionPostgres provisions a new Postgres database.
func (c *Client) ProvisionPostgres(ctx context.Context, token, tier string) (*Credentials, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), provisionTimeout(tier))
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
}

// ProvisionCache provisions a new Redis cache.
func (c *Client) ProvisionCache(ctx context.Context, token, tier string) (*Credentials, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), provisionTimeout(tier))
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
}

// ProvisionNoSQL provisions a new MongoDB database.
func (c *Client) ProvisionNoSQL(ctx context.Context, token, tier string) (*Credentials, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), provisionTimeout(tier))
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
}

// ProvisionQueue provisions a new NATS JetStream queue.
// For pro/team tiers this creates a dedicated NATS pod; for others it uses the shared cluster.
func (c *Client) ProvisionQueue(ctx context.Context, token, tier string) (*Credentials, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), provisionTimeout(tier))
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
}

// StorageBytes fetches current storage usage for a resource.
func (c *Client) StorageBytes(ctx context.Context, token, providerResourceID string, resType commonv1.ResourceType) (int64, error) {
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
}

// DeprovisionResource removes a provisioned resource.
func (c *Client) DeprovisionResource(ctx context.Context, token, providerResourceID string, resType commonv1.ResourceType) error {
	ctx, cancel := context.WithTimeout(c.ctxWithAuth(ctx), 30*time.Second)
	defer cancel()
	_, err := c.grpc.DeprovisionResource(ctx, &provisionerv1.DeprovisionRequest{
		Token:              token,
		ProviderResourceId: providerResourceID,
		ResourceType:       resType,
	})
	if err != nil {
		slog.Error("provisioner.DeprovisionResource failed", "error", err, "token", token)
		return fmt.Errorf("provisioner.DeprovisionResource: %w", err)
	}
	return nil
}
