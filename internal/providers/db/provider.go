package db

import (
	"context"

	"instant.dev/internal/config"
)

// Provider manages Postgres provisioning, delegating to a pluggable Backend.
type Provider struct {
	backend Backend
}

// New creates a Provider using the backend specified in cfg.PostgresProvisionBackend.
func New(cfg *config.Config, customersURL string) *Provider {
	switch cfg.PostgresProvisionBackend {
	case "neon":
		return &Provider{backend: newNeonBackend(cfg.NeonAPIKey, cfg.NeonRegionID)}
	default: // "local"
		return &Provider{backend: newLocalBackend(customersURL, cfg.Environment)}
	}
}

// Provision creates a new Postgres database for the given token.
func (p *Provider) Provision(ctx context.Context, token, tier string) (*Credentials, error) {
	return p.backend.Provision(ctx, token, tier)
}

// ProvisionWithExtensions creates a new Postgres database for the given token
// and installs each requested allowlisted extension (currently "vector" only).
// Pass nil/empty extensions to provision a vanilla database — identical to
// Provision.
func (p *Provider) ProvisionWithExtensions(ctx context.Context, token, tier string, extensions []string) (*Credentials, error) {
	return p.backend.ProvisionWithExtensions(ctx, token, tier, extensions)
}

// StorageBytes returns the storage used by the database for the given token and providerResourceID.
func (p *Provider) StorageBytes(ctx context.Context, token, providerResourceID string) (int64, error) {
	return p.backend.StorageBytes(ctx, token, providerResourceID)
}

// Deprovision removes the database and user for the given token.
func (p *Provider) Deprovision(ctx context.Context, token, providerResourceID string) error {
	return p.backend.Deprovision(ctx, token, providerResourceID)
}
