package storage

// storage_mode.go — naming + derivation for the isolation mode a tenant
// actually gets. Surfaced to customers as the `mode` field in the
// /storage/new response so they can see at a glance what isolation they have.
//
// The mode is derived from the live provider's Capabilities() + the shape of
// the issued credential (session-token presence). It is NOT persisted as a
// separate column — that lets a future operator-side migration to a more-
// isolating backend immediately reflect on every existing resource without
// touching rows. Tenants on legacy DO Spaces rows surface as
// "shared-master-key" until the operator flips OBJECT_STORE_BACKEND=r2.

import (
	"instant.dev/common/storageprovider"
)

// StorageMode is the isolation strength a tenant actually has.
type StorageMode string

const (
	// ModeSharedMasterKey — DO Spaces today: every tenant gets the master
	// key + a prefix-by-convention. The least-isolated mode.
	ModeSharedMasterKey StorageMode = "shared-master-key"

	// ModeBroker — no long-lived credential issued; tenant calls
	// POST /storage/:token/presign to mint short-lived presigned URLs.
	// Used when the backend has no prefix-scoping AND the tenant tier
	// doesn't qualify for a dedicated bucket.
	ModeBroker StorageMode = "broker"

	// ModePrefixScoped — backend ENFORCES s3:prefix at the IAM layer.
	// R2 / S3 / MinIO long-lived path.
	ModePrefixScoped StorageMode = "prefix-scoped"

	// ModePrefixScopedTemporary — same as ModePrefixScoped but with a
	// session token + ExpiresAt (R2 temp-creds, S3 STS).
	ModePrefixScopedTemporary StorageMode = "prefix-scoped-temporary"

	// ModeDedicatedBucket — paid tier on a backend without prefix-scoping;
	// each tenant gets a whole bucket. Reserved (not yet auto-issued).
	ModeDedicatedBucket StorageMode = "dedicated-bucket"
)

// DeriveStorageMode returns the StorageMode label corresponding to a
// provider's Capabilities and the shape of the issued credential.
//
// hasSessionToken is true when the credential carries a SessionToken (STS
// temp creds) so we can distinguish ModePrefixScoped from
// ModePrefixScopedTemporary.
func DeriveStorageMode(caps storageprovider.Capabilities, hasSessionToken bool) StorageMode {
	if !caps.PrefixScopedKeys {
		return ModeSharedMasterKey
	}
	if hasSessionToken {
		return ModePrefixScopedTemporary
	}
	return ModePrefixScoped
}
