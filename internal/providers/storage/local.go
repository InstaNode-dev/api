package storage

// Package storage is the api's adapter into common/storageprovider.
//
// Historically this package held two hard-coded backends (minio-admin and
// shared-key) in one Provider struct. As of 2026-05-20 the credential-
// issuance surface moved into common/storageprovider; this file is now a
// THIN FACADE that wraps any common/storageprovider.StorageCredentialProvider
// and presents the historical Provider.Provision / Deprovision / Backend()
// API the handlers + router were already coded against. That way the
// abstraction lands without rewriting every call site.
//
// The interesting cross-tenant security boundary (full-token prefix; never
// re-derive the IAM identifier from the token) is still enforced here via
// prefixident.go.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"instant.dev/common/storageprovider"

	// Side-effect imports register each backend with the factory.
	_ "instant.dev/common/storageprovider/dospaces"
	_ "instant.dev/common/storageprovider/r2"
	_ "instant.dev/common/storageprovider/s3"
	_ "instant.dev/internal/providers/storage/minio"
)

// Backend is a historical alias for the operator-facing backend selector.
// New code should use storageprovider.NormalizeBackend / Config.Backend.
type Backend string

const (
	// BackendMinIOAdmin uses MinIO's admin API.
	BackendMinIOAdmin Backend = "minio-admin"
	// BackendSharedKey is the legacy DO-Spaces-style master-key pattern.
	// Kept as a name only — the dospaces provider now implements it.
	BackendSharedKey Backend = "shared-key"
	// BackendDOSpaces / BackendR2 / BackendS3 / BackendMinIO are the canonical
	// names used by the new abstraction. Code paths that branch on Backend
	// should switch onto these.
	BackendDOSpaces Backend = "do-spaces"
	BackendR2       Backend = "r2"
	BackendS3       Backend = "s3"
	BackendMinIO    Backend = "minio"
)

// ResolveBackend keeps backwards compat with operators on OBJECT_STORE_MODE.
// It maps every historical alias into the new abstraction's name and back
// onto a Backend value. Empty + unknown → minio-admin (the secure default
// when no backend is explicitly chosen).
func ResolveBackend(mode string) Backend {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "shared-key", "shared", "master", "shared_key":
		return BackendSharedKey
	case "do-spaces", "do_spaces", "dospaces", "do", "digitalocean", "spaces":
		return BackendDOSpaces
	case "r2", "cloudflare", "cf-r2", "cloudflare-r2":
		return BackendR2
	case "s3", "aws", "aws-s3":
		return BackendS3
	case "minio":
		return BackendMinIO
	case "minio-admin", "admin", "iam", "":
		return BackendMinIOAdmin
	default:
		return BackendMinIOAdmin
	}
}

// ErrAdminUnavailable is returned when an admin-mode operation is invoked
// but the admin client could not be constructed.
var ErrAdminUnavailable = errors.New("storage: admin-mode unavailable (missing OBJECT_STORE_ACCESS_KEY/OBJECT_STORE_SECRET_KEY or backend not minio-admin)")

// Credentials is the api-facing credential carrier — kept for backwards
// compatibility with handler/router code that already destructures these
// fields.
//
// StorageMode is the isolation label (see storage_mode.go). Surfaced so the
// handler can echo it back in the /storage/new response without recomputing
// it.
type Credentials struct {
	BucketURL          string
	AccessKeyID        string
	SecretAccessKey    string
	SessionToken       string // empty unless STS / temp-creds path
	Prefix             string
	ProviderResourceID string
	Endpoint           string
	StorageMode        StorageMode
}

// Provider is the api's wrapper around a common/storageprovider provider.
// It carries the historical Backend()/BucketName() helpers + a Provision /
// Deprovision shape that returns the legacy Credentials struct, so handlers
// don't have to change.
type Provider struct {
	impl       storageprovider.StorageCredentialProvider
	backendTag Backend
	bucketName string
	publicURL  string
	endpoint   string
	useTLS     bool
}

// Backend reports the operator-facing backend tag this provider was built
// with. Used by /healthz logging and audit emitters.
func (p *Provider) Backend() Backend {
	if p == nil {
		return ""
	}
	return p.backendTag
}

// BucketName reports the configured shared bucket.
func (p *Provider) BucketName() string {
	if p == nil {
		return ""
	}
	return p.bucketName
}

// Impl returns the underlying storageprovider implementation. Used by the
// presign handler (which needs Capabilities() + master key access to compute
// signed URLs) and by tests that want to inspect what the factory wired in.
func (p *Provider) Impl() storageprovider.StorageCredentialProvider {
	if p == nil {
		return nil
	}
	return p.impl
}

// Capabilities is a convenience pass-through to the underlying impl.
func (p *Provider) Capabilities() storageprovider.Capabilities {
	if p == nil || p.impl == nil {
		return storageprovider.Capabilities{}
	}
	return p.impl.Capabilities()
}

// New constructs a Provider in the historical "minio-admin" mode (used by
// tests and by callers that haven't been updated to NewFromConfig).
func New(endpoint, publicEndpoint, rootUser, rootPassword, bucketName string) (*Provider, error) {
	return NewWithBackend(BackendMinIOAdmin, endpoint, publicEndpoint, rootUser, rootPassword, bucketName, false)
}

// NewWithBackend constructs a Provider, picking the right common/storageprovider
// implementation under the hood. This preserves the historical signature; new
// callers should prefer NewFromConfig for clarity.
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

	cfg := storageprovider.Config{
		Backend:           backendForStorageProvider(backend),
		Endpoint:          endpoint,
		PublicURL:         publicEndpoint,
		Bucket:            bucketName,
		MasterKey:         rootUser,
		MasterSecret:      rootPassword,
		MinIORootUser:     rootUser,
		MinIORootPassword: rootPassword,
		UseTLS:            secure,
	}
	impl, err := storageprovider.Factory(cfg)
	if err != nil {
		return nil, err
	}
	return &Provider{
		impl:       impl,
		backendTag: backend,
		bucketName: bucketName,
		publicURL:  publicEndpoint,
		endpoint:   endpoint,
		useTLS:     secure,
	}, nil
}

// NewFromConfig is the preferred constructor for new code: pass an
// already-built storageprovider.Config and let common's Factory pick the
// implementation. backend is the operator-facing tag used by Backend()
// (informational; the actual impl is whatever Factory returns).
func NewFromConfig(cfg storageprovider.Config) (*Provider, error) {
	impl, err := storageprovider.Factory(cfg)
	if err != nil {
		return nil, err
	}
	return &Provider{
		impl:       impl,
		backendTag: tagForStorageProvider(storageprovider.NormalizeBackend(cfg.Backend)),
		bucketName: cfg.Bucket,
		publicURL:  cfg.PublicURL,
		endpoint:   cfg.Endpoint,
		useTLS:     cfg.UseTLS,
	}, nil
}

// backendForStorageProvider maps the historical Backend enum onto the canonical
// storageprovider name. BackendMinIOAdmin → "minio", BackendSharedKey →
// "do-spaces" (shared-key was always DO-Spaces-style master-key behaviour).
func backendForStorageProvider(b Backend) string {
	switch b {
	case BackendMinIOAdmin:
		return "minio"
	case BackendSharedKey:
		return "do-spaces"
	case BackendDOSpaces:
		return "do-spaces"
	case BackendR2:
		return "r2"
	case BackendS3:
		return "s3"
	case BackendMinIO:
		return "minio"
	default:
		return "minio"
	}
}

func tagForStorageProvider(name string) Backend {
	switch name {
	case "do-spaces":
		return BackendDOSpaces
	case "r2":
		return BackendR2
	case "s3":
		return BackendS3
	case "minio":
		return BackendMinIOAdmin
	}
	return BackendMinIOAdmin
}

// Provision is the historical entry point. It dispatches to the underlying
// storageprovider implementation, honours the full-token prefix invariant,
// and translates the returned TenantCreds back into the legacy Credentials
// shape (BucketURL + AccessKeyID + SecretAccessKey + Prefix +
// ProviderResourceID + Endpoint).
//
// Two cross-cutting behaviours preserved from the old implementation:
//   1. Prefix is always the FULL token (never token[:8]). See prefixident.go.
//   2. ProviderResourceID is the canonical slash-free prefix the api persists
//      so Deprovision / the worker scanner never re-derive it.
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	if p == nil || p.impl == nil {
		return nil, ErrAdminUnavailable
	}

	prefix := objectPrefixForToken(token)
	objectPrefix := prefix + "/"

	creds, err := p.impl.IssueTenantCredentials(ctx, storageprovider.IssueRequest{
		ResourceToken: token,
		Bucket:        p.bucketName,
		Prefix:        prefix,
		TTL:           0, // long-lived; api decides broker-mode at the handler layer.
	})
	if err != nil {
		return nil, fmt.Errorf("storage.Provision: %w", err)
	}

	bucketURL := fmt.Sprintf("%s/%s/%s", p.customerEndpointURL(), p.bucketName, objectPrefix)

	mode := DeriveStorageMode(p.impl.Capabilities(), creds.SessionToken != "")

	slog.Info("storage.Provision",
		"backend", p.backendTag,
		"impl", p.impl.Name(),
		"pattern", mode,
		"token", token,
		"prefix", objectPrefix,
		"tier", tier,
	)

	return &Credentials{
		BucketURL:          bucketURL,
		AccessKeyID:        creds.AccessKey,
		SecretAccessKey:    creds.SecretKey,
		SessionToken:       creds.SessionToken,
		Prefix:             objectPrefix,
		ProviderResourceID: prefix,
		Endpoint:           p.customerEndpointURL(),
		StorageMode:        mode,
	}, nil
}

// Deprovision releases the per-token credentials. For prefix-scoped backends
// this calls RevokeTenantCredentials on the canonical (and legacy) KeyIDs;
// for shared-master-key backends this is a no-op (no per-tenant identity to
// remove). Errors are logged but not fatal.
func (p *Provider) Deprovision(ctx context.Context, token, providerResourceID string) error {
	if p == nil || p.impl == nil {
		return ErrAdminUnavailable
	}

	canonicalPrefix := resolveObjectPrefix(token, providerResourceID)
	candidates := []string{"key_" + canonicalPrefix}
	if legacy := legacyObjectPrefixForToken(token); legacy != "" {
		legacyKey := "key_" + legacy
		if legacyKey != candidates[0] {
			candidates = append(candidates, legacyKey)
		}
	}

	for _, keyID := range candidates {
		if err := p.impl.RevokeTenantCredentials(ctx, keyID); err != nil {
			slog.Warn("storage.Deprovision: revoke failed",
				"backend", p.backendTag,
				"key_id", keyID,
				"error", err,
			)
		}
	}
	slog.Info("storage.Deprovision",
		"backend", p.backendTag,
		"token", token,
		"canonical_key_id", candidates[0],
	)
	return nil
}

// customerEndpointURL composes the customer-facing endpoint URL with scheme.
func (p *Provider) customerEndpointURL() string {
	if p.publicURL != "" {
		if strings.Contains(p.publicURL, "://") {
			return p.publicURL
		}
		scheme := "http"
		if p.useTLS {
			scheme = "https"
		}
		return scheme + "://" + p.publicURL
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
