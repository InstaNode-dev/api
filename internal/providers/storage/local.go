package storage

// Package storage handles S3-compatible object storage provisioning.
//
// Two backends share the same Provider type and customer-facing contract,
// chosen via OBJECT_STORE_MODE (alias OBJECT_STORE_BACKEND) at startup:
//
//   "minio-admin"  — DEFAULT in non-dev environments. The provider talks
//     to MinIO's admin API (`madmin-go/v3`) to mint a dedicated IAM user
//     per token with a prefix-scoped policy. Hard isolation: each
//     customer's access key can only read/write under their own prefix.
//     Required for any Team-tier / compliance-bound customer. Closes
//     the shared-key loophole where every /storage/new caller used to
//     receive the same master access key.
//
//   "shared-key"   — provider-agnostic. The provider holds ONE master
//     access key (sourced from OBJECT_STORE_ACCESS_KEY /
//     OBJECT_STORE_SECRET_KEY) and returns those same credentials to
//     every customer along with their assigned object prefix. Isolation
//     is by prefix convention only — a misbehaving customer with the
//     master key could in principle reach other prefixes; in practice
//     trusted because customers are authenticated to the platform
//     before they ever see the key. Used for DO Spaces / AWS S3 / GCS /
//     R2 / Backblaze B2 / Wasabi / any other S3-compatible service that
//     doesn't expose a portable per-user IAM API. Local-dev only in
//     production builds — the router refuses to start with shared-key
//     when ENVIRONMENT=production unless OBJECT_STORE_ALLOW_SHARED_KEY=1
//     is set as an explicit operator escape hatch.
//
// Credential format (both backends):
//   - AccessKeyID:     key_{token_prefix8} in admin mode, master key in shared mode
//   - SecretAccessKey: 32-char hex random in admin mode, master secret in shared mode
//   - Prefix:          {token_prefix8}/ — same in both modes
//   - BucketURL:       <scheme>://{public_endpoint}/{bucket}/{prefix} — same in both modes
//   - Endpoint:        <scheme>://{public_endpoint} — same in both modes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	madmin "github.com/minio/madmin-go/v3"
	"instant.dev/internal/metrics"
)

// Backend selects the credential-issuance strategy.
type Backend string

const (
	// BackendMinIOAdmin uses MinIO's admin API to mint per-customer IAM users.
	// Hard prefix isolation. Requires the backend to be MinIO (other S3-
	// compatible services don't expose a portable per-user IAM API).
	// This is the secure default — see package doc.
	BackendMinIOAdmin Backend = "minio-admin"

	// BackendSharedKey returns the platform's master credentials to every
	// customer along with their assigned prefix. Trust-based isolation;
	// works against any S3-compatible service (DO Spaces, AWS S3, GCS,
	// R2, B2, Wasabi). Local-dev only in production builds.
	BackendSharedKey Backend = "shared-key"
)

// ErrAdminUnavailable is returned when an admin-mode operation is invoked
// but the admin client could not be constructed (missing credentials or
// the configured backend is shared-key). Callers should surface this as a
// 503 to the customer rather than silently falling back to shared-key.
var ErrAdminUnavailable = errors.New("storage: admin-mode unavailable (missing OBJECT_STORE_ACCESS_KEY/OBJECT_STORE_SECRET_KEY or backend not minio-admin)")

// ResolveBackend normalises the operator-facing mode string into a Backend
// value. Accepts the historical aliases ("admin", "minio", "iam") for
// minio-admin and ("shared", "master") for shared-key. Empty string and
// unknown values both resolve to BackendMinIOAdmin — the secure default.
//
// The router uses this so OBJECT_STORE_MODE=admin (the documented default)
// always lands on the per-customer IAM-user path, even on operators who
// haven't migrated from the legacy OBJECT_STORE_BACKEND=minio-admin env.
func ResolveBackend(mode string) Backend {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shared-key", "shared", "master", "shared_key":
		return BackendSharedKey
	case "minio-admin", "admin", "minio", "iam", "":
		return BackendMinIOAdmin
	default:
		return BackendMinIOAdmin
	}
}

// Credentials holds the S3-compatible storage access details.
type Credentials struct {
	// BucketURL is the S3 endpoint URL for this prefix.
	// Format: <scheme>://{endpoint}/{bucket}/{prefix}
	BucketURL string

	// AccessKeyID is the S3 access key for this resource.
	// minio-admin mode: per-customer "key_{prefix8}".
	// shared-key mode: the platform's master access key (same value for every customer).
	AccessKeyID string

	// SecretAccessKey is the S3 secret.
	// minio-admin mode: 32-char hex random, generated at provision time.
	// shared-key mode: the platform's master secret (same value for every customer).
	SecretAccessKey string

	// Prefix is the object key prefix for this resource (e.g. "a1b2c3d4/").
	// The customer is expected to scope all reads/writes to this prefix.
	Prefix string

	// Endpoint is the S3-compatible endpoint URL
	// (e.g. "http://minio.instant-data.svc.cluster.local:9000" or
	// "https://nyc3.digitaloceanspaces.com").
	Endpoint string
}

// Provider manages S3-compatible storage provisioning.
type Provider struct {
	backend    Backend
	madmClient *madmin.AdminClient // populated only when backend == BackendMinIOAdmin

	// shared-key mode credentials (also used as master for minio-admin mode internally).
	masterAccessKey string
	masterSecretKey string

	endpoint       string // internal host:port for admin/bucket ops, e.g. "minio.instant-data.svc.cluster.local:9000"
	publicEndpoint string // host:port returned to customers (falls back to endpoint when empty)
	bucketName     string // e.g. "instant-shared"
}

// Backend reports the credential-issuance strategy this provider was
// constructed with. Callers (router, /healthz, audit emitters) use this
// to log which isolation mode is in effect at runtime.
func (p *Provider) Backend() Backend {
	if p == nil {
		return ""
	}
	return p.backend
}

// BucketName reports the configured shared-bucket name. Exposed so
// operator-facing endpoints (e.g. /internal/storage-self-check) can
// display the bucket without reaching into config.
func (p *Provider) BucketName() string {
	if p == nil {
		return ""
	}
	return p.bucketName
}

// New creates a Provider in MinIO admin mode (current behavior — kept for
// backward compatibility with callers that haven't been updated to
// NewWithBackend).
//
// endpoint is the cluster-internal "host:port" used for IAM/bucket admin calls.
// publicEndpoint is the customer-reachable address returned in BucketURL/Endpoint.
// Accepts either bare "host[:port]" (defaults to http://) or a scheme-prefixed
// "https://host" / "http://host[:port]" form for TLS-terminated public hostnames.
// When empty, it falls back to endpoint (legacy in-cluster behavior).
// rootUser/rootPassword are the MinIO root credentials.
func New(endpoint, publicEndpoint, rootUser, rootPassword, bucketName string) (*Provider, error) {
	return NewWithBackend(BackendMinIOAdmin, endpoint, publicEndpoint, rootUser, rootPassword, bucketName, false)
}

// NewWithBackend creates a Provider in either MinIO admin or shared-key mode.
//
// secure=true tells the SDK to use HTTPS for admin calls (required for DO
// Spaces / AWS S3 / any TLS-terminated endpoint). The customer-facing
// scheme is derived independently from publicEndpoint's prefix.
func NewWithBackend(backend Backend, endpoint, publicEndpoint, rootUser, rootPassword, bucketName string, secure bool) (*Provider, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("storage: endpoint is required")
	}
	if bucketName == "" {
		bucketName = "instant-shared"
	}
	if rootUser == "" || rootPassword == "" {
		return nil, fmt.Errorf("storage: master access key + secret are required (OBJECT_STORE_ACCESS_KEY / OBJECT_STORE_SECRET_KEY)")
	}

	p := &Provider{
		backend:         backend,
		masterAccessKey: rootUser,
		masterSecretKey: rootPassword,
		endpoint:        endpoint,
		publicEndpoint:  publicEndpoint,
		bucketName:      bucketName,
	}

	if backend == BackendMinIOAdmin {
		madmClient, err := madmin.New(endpoint, rootUser, rootPassword, secure)
		if err != nil {
			return nil, fmt.Errorf("storage: create MinIO admin client for %s: %w", endpoint, err)
		}
		p.madmClient = madmClient
	}

	return p, nil
}

// customerEndpoint returns the host[:port] to surface to customers, stripped of
// scheme.
func (p *Provider) customerEndpoint() string {
	raw := p.publicEndpoint
	if raw == "" {
		raw = p.endpoint
	}
	// Strip a leading scheme if present (e.g. "https://s3.instanode.dev" → "s3.instanode.dev").
	if i := strings.Index(raw, "://"); i > 0 {
		return raw[i+3:]
	}
	return raw
}

// customerScheme returns the URL scheme to surface to customers ("http" or "https").
// Derived from publicEndpoint when it carries an explicit scheme; otherwise "http"
// to preserve the historical in-cluster MinIO default.
func (p *Provider) customerScheme() string {
	if p.publicEndpoint == "" {
		return "http"
	}
	if strings.HasPrefix(p.publicEndpoint, "https://") {
		return "https"
	}
	if strings.HasPrefix(p.publicEndpoint, "http://") {
		return "http"
	}
	return "http"
}

// Provision creates a per-token storage resource and returns S3-compatible
// credentials. The caller can use any S3 SDK with the returned endpoint,
// access key, secret, and prefix.
//
// In minio-admin mode, this mints a dedicated IAM user with a prefix-scoped
// policy. In shared-key mode, this is a constant-time call that just
// computes the prefix and returns the master key (no remote calls).
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	objectPrefix := prefix + "/" // e.g. "a1b2c3d4/"

	customerHost := p.customerEndpoint()
	scheme := p.customerScheme()
	bucketURL := fmt.Sprintf("%s://%s/%s/%s", scheme, customerHost, p.bucketName, objectPrefix)
	endpoint := fmt.Sprintf("%s://%s", scheme, customerHost)

	switch p.backend {
	case BackendSharedKey:
		// Shared-key mode: every customer gets the same master access key
		// + their assigned prefix. Customer is on the honor system to stay
		// within their prefix; the platform doesn't enforce it at the
		// object-store level because not every S3 backend supports
		// per-user IAM (DO Spaces, GCS, R2, etc.).
		slog.Info("storage.Provision: shared-key credentials issued",
			"backend", p.backend,
			"token", token,
			"prefix", objectPrefix,
			"tier", tier,
		)
		return &Credentials{
			BucketURL:       bucketURL,
			AccessKeyID:     p.masterAccessKey,
			SecretAccessKey: p.masterSecretKey,
			Prefix:          objectPrefix,
			Endpoint:        endpoint,
		}, nil

	case BackendMinIOAdmin:
		accessKeyID := "key_" + prefix // e.g. "key_a1b2c3d4"
		policyName := "pol_" + prefix  // e.g. "pol_a1b2c3d4"

		// Generate 32-char hex (16-byte) secret access key.
		secretBytes := make([]byte, 16)
		if _, err := rand.Read(secretBytes); err != nil {
			return nil, fmt.Errorf("storage.Provision: generate secret: %w", err)
		}
		secretAccessKey := hex.EncodeToString(secretBytes)

		if p.madmClient == nil {
			return nil, ErrAdminUnavailable
		}

		// Create the MinIO IAM user.
		if err := p.madmClient.AddUser(ctx, accessKeyID, secretAccessKey); err != nil {
			metrics.StorageIAMUsersFailed.WithLabelValues("create", "add_user").Inc()
			return nil, fmt.Errorf("storage.Provision: AddUser %q: %w", accessKeyID, err)
		}

		// Create prefix-scoped IAM policy.
		policyJSON, err := json.Marshal(p.buildPolicy(objectPrefix))
		if err != nil {
			_ = p.madmClient.RemoveUser(ctx, accessKeyID)
			metrics.StorageIAMUsersFailed.WithLabelValues("create", "marshal_policy").Inc()
			return nil, fmt.Errorf("storage.Provision: marshal policy: %w", err)
		}
		if err := p.madmClient.AddCannedPolicy(ctx, policyName, policyJSON); err != nil {
			_ = p.madmClient.RemoveUser(ctx, accessKeyID)
			metrics.StorageIAMUsersFailed.WithLabelValues("create", "add_policy").Inc()
			return nil, fmt.Errorf("storage.Provision: AddCannedPolicy %q: %w", policyName, err)
		}

		// Attach policy to user.
		if err := p.madmClient.SetPolicy(ctx, policyName, accessKeyID, false); err != nil {
			_ = p.madmClient.RemoveUser(ctx, accessKeyID)
			_ = p.madmClient.RemoveCannedPolicy(ctx, policyName)
			metrics.StorageIAMUsersFailed.WithLabelValues("create", "set_policy").Inc()
			return nil, fmt.Errorf("storage.Provision: SetPolicy %q → %q: %w", policyName, accessKeyID, err)
		}

		metrics.StorageIAMUsersCreated.Inc()
		slog.Info("storage.Provision: MinIO user created",
			"backend", p.backend,
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

	default:
		return nil, fmt.Errorf("storage.Provision: unknown backend %q (valid: minio-admin, shared-key)", p.backend)
	}
}

// Deprovision releases the per-token resources allocated at Provision time.
// In minio-admin mode this removes the IAM user + policy. In shared-key mode
// this is a no-op because no per-token resources were created.
//
// Errors are logged but not fatal — the resource record will be soft-deleted
// by the caller regardless.
func (p *Provider) Deprovision(ctx context.Context, token string) error {
	if p.backend == BackendSharedKey {
		// No per-customer IAM resources were created; nothing to release.
		// Object cleanup (deleting the customer's prefix) is the caller's
		// responsibility via a separate object-list-and-delete loop if
		// they want zero-byte deprovisioning. For 24h-TTL anonymous tier
		// this isn't worth running on every deprovision — the prefix
		// will simply remain unused until the bucket's lifecycle policy
		// reaps it (configure an object-expiry rule on the bucket).
		slog.Info("storage.Deprovision: shared-key mode — no IAM resources to release",
			"backend", p.backend, "token", token)
		return nil
	}

	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	accessKeyID := "key_" + prefix
	policyName := "pol_" + prefix

	if p.madmClient == nil {
		return ErrAdminUnavailable
	}

	var failed bool
	if err := p.madmClient.RemoveUser(ctx, accessKeyID); err != nil {
		failed = true
		metrics.StorageIAMUsersFailed.WithLabelValues("delete", "remove_user").Inc()
		slog.Warn("storage.Deprovision: RemoveUser failed",
			"access_key_id", accessKeyID, "error", err)
	}
	if err := p.madmClient.RemoveCannedPolicy(ctx, policyName); err != nil {
		failed = true
		metrics.StorageIAMUsersFailed.WithLabelValues("delete", "remove_policy").Inc()
		slog.Warn("storage.Deprovision: RemoveCannedPolicy failed",
			"policy_name", policyName, "error", err)
	}
	if !failed {
		metrics.StorageIAMUsersDeleted.Inc()
	}

	slog.Info("storage.Deprovision: MinIO user and policy removed",
		"token", token, "access_key_id", accessKeyID)
	return nil
}

// iamPolicy is used for JSON serialization of S3 IAM policies (minio-admin only).
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

// condMap is the inner map of an IAM Condition block, e.g.
//
//	{"StringLike": {"s3:prefix": ["a1b2c3d4/*"]}}
//
// The outer key is the operator ("StringLike"); the inner map carries the
// per-key value list.
type condMap map[string][]string

// buildPolicy returns an IAM policy that allows the minimum read+write+
// list surface the customer needs against their own prefix:
//
//   - s3:GetObject + s3:PutObject + s3:DeleteObject on
//     arn:aws:s3:::{bucket}/{prefix}/*
//   - s3:ListBucket on arn:aws:s3:::{bucket} BUT scoped by an
//     s3:prefix StringLike condition so the customer can only list
//     keys under their prefix — never enumerate sibling tenants.
//
// Only used in minio-admin mode. This is the policy that closes the
// shared-key loophole: even if the customer somehow obtains the IAM
// user's secret, they cannot read another tenant's objects.
func (p *Provider) buildPolicy(objectPrefix string) iamPolicy {
	pfx := strings.TrimSuffix(objectPrefix, "/")
	return iamPolicy{
		Version: "2012-10-17",
		Statement: []iamStatement{
			{
				Effect:   "Allow",
				Action:   []string{"s3:GetObject", "s3:PutObject", "s3:DeleteObject"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s/%s/*", p.bucketName, pfx)},
			},
			{
				Effect:   "Allow",
				Action:   []string{"s3:ListBucket"},
				Resource: []string{fmt.Sprintf("arn:aws:s3:::%s", p.bucketName)},
				Condition: map[string]condMap{
					"StringLike": {
						"s3:prefix": []string{pfx + "/*"},
					},
				},
			},
		},
	}
}
