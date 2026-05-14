package db

import (
	"context"
	"fmt"
)

// Backend is the interface every Postgres provisioning backend must implement.
//
// ProvisionWithExtensions accepts an optional list of Postgres extension
// names to install in the freshly-created database (e.g. []string{"vector"}
// for pgvector). The implementation MUST allowlist the names — only the
// extensions in AllowedExtensions are permitted to flow through. An empty
// or nil slice provisions a vanilla database (identical to Provision).
//
// Provision is kept as a convenience wrapper that calls
// ProvisionWithExtensions(ctx, token, tier, nil) so existing callers don't
// have to plumb the extensions argument.
type Backend interface {
	Provision(ctx context.Context, token, tier string) (*Credentials, error)
	ProvisionWithExtensions(ctx context.Context, token, tier string, extensions []string) (*Credentials, error)
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

// AllowedExtensions is the closed set of Postgres extensions the provisioner
// is permitted to install on a newly-created database. We deliberately keep
// this tiny and explicit — allowing arbitrary CREATE EXTENSION would let
// callers reach into superuser-only contrib modules (pg_stat_statements,
// file_fdw, etc.) and break tenant isolation. Add new entries here only
// after a security review of the underlying extension.
var AllowedExtensions = map[string]bool{
	"vector": true,
}

// ValidateExtensions returns an error if any extension is not on the allowlist.
// Returns nil for an empty/nil slice (no extensions requested).
func ValidateExtensions(extensions []string) error {
	for _, ext := range extensions {
		if !AllowedExtensions[ext] {
			return fmt.Errorf("db: extension %q is not on the allowlist (allowed: vector)", ext)
		}
	}
	return nil
}
