package storage

// Package storage handles S3-compatible object storage provisioning via MinIO.
//
// Each provisioned token gets a dedicated MinIO IAM user scoped to a prefix
// within the shared "instant-shared" bucket. Isolation is enforced by the
// IAM policy: the user can only read/write objects under their prefix.
//
// Credential format:
//   - AccessKeyID:     key_{token_prefix8}   (e.g. "key_a1b2c3d4")
//   - SecretAccessKey: 32-char hex random
//   - Prefix:          {token_prefix8}/
//   - BucketURL:       http://{endpoint}/{bucket}/{prefix}
//
// S3 endpoint for callers: http://{MINIO_ENDPOINT}
// Bucket: MINIO_BUCKET_NAME (default: "instant-shared")

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	madmin "github.com/minio/madmin-go/v3"
)

// Credentials holds the S3-compatible storage access details.
type Credentials struct {
	// BucketURL is the S3 endpoint URL for this prefix.
	// Format: http://{endpoint}/{bucket}/{prefix}
	BucketURL string

	// AccessKeyID is the S3 access key for this resource.
	// Format: key_{token_prefix8}
	AccessKeyID string

	// SecretAccessKey is the S3 secret (32-char hex).
	SecretAccessKey string

	// Prefix is the object key prefix for this resource (e.g. "a1b2c3d4/").
	Prefix string

	// Endpoint is the S3-compatible endpoint URL (e.g. "http://minio.instant-data.svc.cluster.local:9000").
	Endpoint string
}

// Provider manages MinIO storage provisioning.
type Provider struct {
	madmClient     *madmin.AdminClient
	endpoint       string // internal host:port for admin/bucket ops, e.g. "minio.instant-data.svc.cluster.local:9000"
	publicEndpoint string // host:port returned to customers (falls back to endpoint when empty)
	bucketName     string // e.g. "instant-shared"
}

// New creates a Provider backed by a MinIO admin client.
//
// endpoint is the cluster-internal "host:port" used for IAM/bucket admin calls.
// publicEndpoint is the customer-reachable address returned in BucketURL/Endpoint.
// Accepts either bare "host[:port]" (defaults to http://) or a scheme-prefixed
// "https://host" / "http://host[:port]" form for TLS-terminated public hostnames.
// When empty, it falls back to endpoint (legacy in-cluster behavior).
// rootUser/rootPassword are the MinIO root credentials.
func New(endpoint, publicEndpoint, rootUser, rootPassword, bucketName string) (*Provider, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("storage: MinIO endpoint is required (MINIO_ENDPOINT)")
	}
	if bucketName == "" {
		bucketName = "instant-shared"
	}

	madmClient, err := madmin.New(endpoint, rootUser, rootPassword, false /* no TLS */)
	if err != nil {
		return nil, fmt.Errorf("storage: create MinIO admin client for %s: %w", endpoint, err)
	}

	return &Provider{
		madmClient:     madmClient,
		endpoint:       endpoint,
		publicEndpoint: publicEndpoint,
		bucketName:     bucketName,
	}, nil
}

// customerEndpoint returns the host[:port] to surface to customers, stripped of
// any scheme. Falls back to the internal endpoint when no public override is set.
func (p *Provider) customerEndpoint() string {
	raw := p.publicEndpoint
	if raw == "" {
		raw = p.endpoint
	}
	// Strip a leading scheme if present (e.g. "https://s3.instanode.dev" → "s3.instanode.dev").
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	return strings.TrimRight(raw, "/")
}

// customerScheme returns the URL scheme to surface to customers ("http" or "https").
// Derived from publicEndpoint when it carries an explicit scheme; otherwise "http"
// to preserve in-cluster legacy behavior.
func (p *Provider) customerScheme() string {
	if p.publicEndpoint == "" {
		return "http"
	}
	if strings.HasPrefix(p.publicEndpoint, "https://") {
		return "https"
	}
	return "http"
}

// Provision creates a MinIO IAM user scoped to a per-token prefix and returns
// S3-compatible credentials. The caller can use any S3 SDK with the returned
// endpoint, access key, secret, and prefix.
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	accessKeyID := "key_" + prefix // e.g. "key_a1b2c3d4"
	policyName := "pol_" + prefix  // e.g. "pol_a1b2c3d4"
	objectPrefix := prefix + "/"   // e.g. "a1b2c3d4/"

	// Generate 32-char hex (16-byte) secret access key.
	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("storage.Provision: generate secret: %w", err)
	}
	secretAccessKey := hex.EncodeToString(secretBytes)

	// Create the MinIO IAM user.
	if err := p.madmClient.AddUser(ctx, accessKeyID, secretAccessKey); err != nil {
		return nil, fmt.Errorf("storage.Provision: AddUser %q: %w", accessKeyID, err)
	}

	// Create prefix-scoped IAM policy.
	policyJSON, err := json.Marshal(p.buildPolicy(objectPrefix))
	if err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		return nil, fmt.Errorf("storage.Provision: marshal policy: %w", err)
	}
	if err := p.madmClient.AddCannedPolicy(ctx, policyName, policyJSON); err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		return nil, fmt.Errorf("storage.Provision: AddCannedPolicy %q: %w", policyName, err)
	}

	// Attach policy to user.
	if err := p.madmClient.SetPolicy(ctx, policyName, accessKeyID, false); err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		_ = p.madmClient.RemoveCannedPolicy(ctx, policyName)
		return nil, fmt.Errorf("storage.Provision: SetPolicy %q → %q: %w", policyName, accessKeyID, err)
	}

	customerHost := p.customerEndpoint()
	scheme := p.customerScheme()
	bucketURL := fmt.Sprintf("%s://%s/%s/%s", scheme, customerHost, p.bucketName, objectPrefix)
	endpoint := fmt.Sprintf("%s://%s", scheme, customerHost)

	slog.Info("storage.Provision: MinIO user created",
		"token", token,
		"access_key_id", accessKeyID,
		"prefix", objectPrefix,
		"tier", tier,
	)

	return &Credentials{
		BucketURL:       bucketURL,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Prefix:          objectPrefix,
		Endpoint:        endpoint,
	}, nil
}

// Deprovision removes the MinIO IAM user and policy for the given token.
// Errors are logged but not fatal — the resource record will be soft-deleted.
func (p *Provider) Deprovision(ctx context.Context, token string) error {
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	accessKeyID := "key_" + prefix
	policyName := "pol_" + prefix

	if err := p.madmClient.RemoveUser(ctx, accessKeyID); err != nil {
		slog.Warn("storage.Deprovision: RemoveUser failed",
			"access_key_id", accessKeyID, "error", err)
	}
	if err := p.madmClient.RemoveCannedPolicy(ctx, policyName); err != nil {
		slog.Warn("storage.Deprovision: RemoveCannedPolicy failed",
			"policy_name", policyName, "error", err)
	}

	slog.Info("storage.Deprovision: MinIO user and policy removed",
		"token", token, "access_key_id", accessKeyID)
	return nil
}

// iamPolicy is used for JSON serialization of S3 IAM policies.
type iamPolicy struct {
	Version   string         `json:"Version"`
	Statement []iamStatement `json:"Statement"`
}

type iamStatement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// buildPolicy returns an IAM policy that allows s3:* only on the given prefix
// within the shared bucket, plus ListBucket on the bucket itself (required for
// prefix-scoped listings).
func (p *Provider) buildPolicy(objectPrefix string) iamPolicy {
	pfx := strings.TrimSuffix(objectPrefix, "/")
	return iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{
			{
				Effect:   "Allow",
				Action:   []string{"s3:*"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s/%s/*", p.bucketName, pfx)},
			},
			{
				Effect:   "Allow",
				Action:   []string{"s3:ListBucket"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s", p.bucketName)},
			},
		},
	}
}
