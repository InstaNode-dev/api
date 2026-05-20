// Package minio implements StorageCredentialProvider against a self-hosted
// MinIO cluster.
//
// MinIO has a portable per-tenant IAM admin API (madmin-go), which means
// PrefixScopedKeys is ENFORCED at the IAM layer: a tenant's access key
// literally cannot reach another tenant's prefix. Used for local development
// and for any operator who runs MinIO instead of a public S3-compatible
// service.
//
// This is the "reference" backend for the abstraction: every other backend
// is trying to match the isolation MinIO already provides.
//
// Lives in `api/internal/providers/storage/minio/` rather than under
// `common/storageprovider/minio/` so that `common` stays free of the
// madmin-go transitive dependency (madmin pulls in MinIO server packages
// that aren't needed by tooling that just wants the interface).
package minio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	madmin "github.com/minio/madmin-go/v3"
	"instant.dev/common/storageprovider"
)

// Name is the canonical backend identifier.
const Name = "minio"

// Provider implements StorageCredentialProvider for MinIO.
type Provider struct {
	endpoint     string
	publicURL    string
	region       string
	bucket       string
	masterKey    string
	masterSecret string
	useTLS       bool
	madmClient   *madmin.AdminClient
}

// New constructs a MinIO provider from cfg.
func New(cfg storageprovider.Config) (storageprovider.StorageCredentialProvider, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("minio: OBJECT_STORE_ENDPOINT is required")
	}
	access := cfg.MasterKey
	if access == "" {
		access = cfg.MinIORootUser
	}
	secret := cfg.MasterSecret
	if secret == "" {
		secret = cfg.MinIORootPassword
	}
	if access == "" || secret == "" {
		return nil, fmt.Errorf("minio: master root user + password are required " +
			"(OBJECT_STORE_ACCESS_KEY / OBJECT_STORE_SECRET_KEY or MINIO_ROOT_USER / MINIO_ROOT_PASSWORD)")
	}
	bucket := cfg.Bucket
	if bucket == "" {
		bucket = "instant-shared"
	}
	madmClient, err := madmin.New(endpoint, access, secret, cfg.UseTLS)
	if err != nil {
		return nil, fmt.Errorf("minio: build admin client: %w", err)
	}
	return &Provider{
		endpoint:     endpoint,
		publicURL:    cfg.PublicURL,
		region:       cfg.Region,
		bucket:       bucket,
		masterKey:    access,
		masterSecret: secret,
		useTLS:       cfg.UseTLS,
		madmClient:   madmClient,
	}, nil
}

// Name returns "minio".
func (p *Provider) Name() string { return Name }

// Capabilities reports MinIO's actual isolation surface.
//
//   - PrefixScopedKeys=true   → enforced at the IAM layer via canned policy
//   - BucketScopedKeys=true
//   - STS=true                → MinIO supports AssumeRoleWithWebIdentity
//   - BucketPerTenant=true    → effectively unbounded
//   - MaxKeysPerAccount=0     → no hard cap
func (p *Provider) Capabilities() storageprovider.Capabilities {
	return storageprovider.Capabilities{
		PrefixScopedKeys:  true,
		BucketScopedKeys:  true,
		STS:               true,
		BucketPerTenant:   true,
		ServerAccessLogs:  true,
		MaxKeysPerAccount: 0,
	}
}

// IssueTenantCredentials mints a per-tenant MinIO IAM user with a prefix-
// scoped canned policy. The returned KeyID is the access key id, which
// RevokeTenantCredentials uses to clean up.
//
// MinIO has no built-in STS endpoint that the abstraction can drive (the one
// that exists requires a configured external IdP), so TTL is always ignored
// here — credentials are long-lived. Callers that need expiry should layer
// their own rotation policy on top.
func (p *Provider) IssueTenantCredentials(ctx context.Context, in storageprovider.IssueRequest) (*storageprovider.TenantCreds, error) {
	prefix := strings.TrimSuffix(strings.TrimSpace(in.Prefix), "/")
	if prefix == "" {
		prefix = in.ResourceToken
	}
	bucket := in.Bucket
	if bucket == "" {
		bucket = p.bucket
	}

	accessKeyID := "key_" + prefix
	policyName := "pol_" + prefix

	secretBytes := make([]byte, 16)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("minio.IssueTenantCredentials: generate secret: %w", err)
	}
	secretAccessKey := hex.EncodeToString(secretBytes)

	if err := p.madmClient.AddUser(ctx, accessKeyID, secretAccessKey); err != nil {
		return nil, fmt.Errorf("minio.IssueTenantCredentials: AddUser %q: %w", accessKeyID, err)
	}

	policyJSON, err := json.Marshal(buildPolicy(bucket, prefix))
	if err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		return nil, fmt.Errorf("minio.IssueTenantCredentials: marshal policy: %w", err)
	}
	if err := p.madmClient.AddCannedPolicy(ctx, policyName, policyJSON); err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		return nil, fmt.Errorf("minio.IssueTenantCredentials: AddCannedPolicy %q: %w", policyName, err)
	}
	if err := p.madmClient.SetPolicy(ctx, policyName, accessKeyID, false); err != nil {
		_ = p.madmClient.RemoveUser(ctx, accessKeyID)
		_ = p.madmClient.RemoveCannedPolicy(ctx, policyName)
		return nil, fmt.Errorf("minio.IssueTenantCredentials: SetPolicy %q→%q: %w", policyName, accessKeyID, err)
	}

	slog.Info("minio.IssueTenantCredentials",
		"backend", Name,
		"pattern", "prefix-scoped-iam-user",
		"token", in.ResourceToken,
		"bucket", bucket,
		"prefix", prefix,
		"access_key_id", accessKeyID,
	)

	return &storageprovider.TenantCreds{
		AccessKey: accessKeyID,
		SecretKey: secretAccessKey,
		Endpoint:  p.customerEndpointURL(),
		Region:    p.region,
		Bucket:    bucket,
		Prefix:    prefix,
		ExpiresAt: nil,
		KeyID:     accessKeyID,
	}, nil
}

// RevokeTenantCredentials removes the IAM user + canned policy. Idempotent
// (MinIO returns no error for unknown identifiers).
func (p *Provider) RevokeTenantCredentials(ctx context.Context, keyID string) error {
	if keyID == "" {
		return nil
	}
	policyName := "pol_" + strings.TrimPrefix(keyID, "key_")
	if err := p.madmClient.RemoveUser(ctx, keyID); err != nil {
		slog.Warn("minio.RevokeTenantCredentials: RemoveUser", "key_id", keyID, "error", err)
	}
	if err := p.madmClient.RemoveCannedPolicy(ctx, policyName); err != nil {
		slog.Warn("minio.RevokeTenantCredentials: RemoveCannedPolicy", "policy_name", policyName, "error", err)
	}
	slog.Info("minio.RevokeTenantCredentials",
		"backend", Name,
		"key_id", keyID,
	)
	return nil
}

// MasterAccessKey / MasterSecretKey expose the platform credentials so the
// api can compute presigned URLs in broker mode if it ever wants to (MinIO
// supports broker mode, the api just doesn't need it because admin mode
// gives real isolation).
func (p *Provider) MasterAccessKey() string { return p.masterKey }
func (p *Provider) MasterSecretKey() string { return p.masterSecret }
func (p *Provider) Endpoint() string        { return p.endpoint }
func (p *Provider) Bucket() string          { return p.bucket }
func (p *Provider) Region() string          { return p.region }
func (p *Provider) PublicURL() string       { return p.customerEndpointURL() }

func (p *Provider) customerEndpointURL() string {
	if p.publicURL != "" {
		return p.publicURL
	}
	scheme := "http"
	if p.useTLS {
		scheme = "https"
	}
	host := p.endpoint
	if strings.Contains(host, "://") {
		return host
	}
	return scheme + "://" + host
}

// iamPolicy + iamStatement + condMap mirror IAM JSON shape.
type iamPolicy struct {
	Version   string         `json:"Version"`
	Statement []iamStatement `json:"Statement"`
}

type iamStatement struct {
	Effect    string             `json:"Effect"`
	Action    []string           `json:"Action"`
	Resource  []string           `json:"Resource"`
	Condition map[string]condMap `json:"Condition,omitempty"`
}

type condMap map[string][]string

func buildPolicy(bucket, prefix string) iamPolicy {
	return iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{
			{
				Effect:   "Allow",
				Action:   []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s/%s/*", bucket, prefix)},
			},
			{
				Effect:   "Allow",
				Action:   []string{"s3:ListBucket"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s", bucket)},
				Condition: map[string]condMap{
					"StringLike": {
						"s3:prefix": []string{prefix + "/*"},
					},
				},
			},
		},
	}
}

func init() {
	storageprovider.Register(Name, New)
}
