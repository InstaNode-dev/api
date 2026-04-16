package db

import "context"

// Backend is the interface every Postgres provisioning backend must implement.
type Backend interface {
	Provision(ctx context.Context, token, tier string) (*Credentials, error)
	StorageBytes(ctx context.Context, token, providerResourceID string) (int64, error)
	Deprovision(ctx context.Context, token, providerResourceID string) error
}

// Credentials returned by Provision.
type Credentials struct {
	URL                string // postgres://usr_{token}:{pass}@host/db_{token}
	DatabaseName       string // db_{token}
	Username           string // usr_{token}
	ProviderResourceID string // Neon project ID, empty for local
}
