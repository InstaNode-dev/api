package storage

import "strings"

// prefixident.go — canonical object-key-prefix helper for the storage backend.
//
// # Why this exists (token-truncation class, P1 BUGHUNT-REPORT-2026-05-17-round2)
//
// The storage backend used to derive every customer's object-key prefix by
// truncating the resource token to its first 8 hex characters:
//
//	prefix := token; if len(prefix) > 8 { prefix = prefix[:8] }
//	objectPrefix := prefix + "/"
//
// In shared-key mode (DO Spaces / S3 / GCS / R2 / B2 — every backend that has
// no portable per-user IAM API) tenant isolation is by prefix CONVENTION only:
// every customer holds the same master key and is trusted to stay within their
// prefix. An 8-hex-char prefix has only 2^32 values, so two distinct storage
// tokens that share their first 8 characters get the SAME object prefix —
// tenant B's master key, scoped to "abc12345/", reads and overwrites tenant
// A's objects. This is a tenant-isolation security boundary; it must not
// depend on an 8-char collision not happening.
//
// # The fix: full-token prefix, stored at provision time, never re-derived
//
// New provisions use objectPrefixForToken(token) — the FULL token — so the
// prefix collides only on a genuine token collision (cryptographic
// improbability). The provider returns the canonical prefix (slash-stripped)
// as Credentials.ProviderResourceID; the api persists it on the resource row's
// provider_resource_id column. Deprovision resolves the prefix via
// resolveObjectPrefix(): the STORED value when present, the full-token
// derivation otherwise.
//
// Legacy rows (provisioned before this fix, provider_resource_id empty/NULL)
// have their objects under the old token[:8] prefix. resolveObjectPrefix falls
// back to legacyObjectPrefixForToken() for them, so existing storage resources
// keep reading their existing objects unchanged — NO object migration, no data
// move. The worker's storage scanner (worker/internal/jobs/storage_minio.go)
// applies the identical resolution order.

// legacyObjectPrefixTokenLen is the truncation length used by the pre-fix
// object-key-prefix scheme (token[:8]). Retained ONLY so the prefix of a
// storage resource provisioned before the token-truncation fix can still be
// located for teardown / scanning. New provisions never use it.
const legacyObjectPrefixTokenLen = 8

// objectPrefixForToken returns the canonical object-key prefix for a storage
// token WITHOUT a trailing slash: the FULL token, never a truncated prefix, so
// two tokens can never collide on the same object namespace.
func objectPrefixForToken(token string) string {
	return token
}

// legacyObjectPrefixForToken returns the pre-fix 8-char-prefix object key
// prefix (no trailing slash) for a token, or "" when the token is too short to
// have been truncated (the canonical prefix already equals the legacy one).
func legacyObjectPrefixForToken(token string) string {
	if len(token) <= legacyObjectPrefixTokenLen {
		return ""
	}
	return token[:legacyObjectPrefixTokenLen]
}

// minioAccessKeyIDPrefix / minioPolicyNamePrefix are the fixed prefixes for
// the per-tenant MinIO IAM user and policy created in minio-admin mode.
const (
	minioAccessKeyIDPrefix = "key_"
	minioPolicyNamePrefix  = "pol_"
)

// minioAccessKeyID returns the MinIO IAM access-key ID for a given object
// prefix (the slash-free canonical prefix). With the full-token prefix this is
// "key_<full-token>" — long enough that two tokens never collide on one IAM
// user, which an 8-char-truncated "key_<token[:8]>" did.
func minioAccessKeyID(prefix string) string {
	return minioAccessKeyIDPrefix + prefix
}

// minioPolicyName returns the MinIO IAM canned-policy name for a given object
// prefix. "pol_<full-token>".
func minioPolicyName(prefix string) string {
	return minioPolicyNamePrefix + prefix
}

// resolveObjectPrefix returns the object-key prefix (no trailing slash) a
// lifecycle operation (Deprovision) must target for a storage resource.
//
// It prefers the providerResourceID stamped on the resource row at provision
// time — the EXACT prefix the provider issued, so no re-derivation can drift.
// It falls back to the canonical full-token derivation when providerResourceID
// is empty, which covers rows provisioned by a build that has this fix but
// where the caller did not thread providerResourceID through. A genuinely
// legacy row (provisioned before the fix) has its objects under
// legacyObjectPrefixForToken(token); callers that must reach those probe the
// legacy form in addition.
func resolveObjectPrefix(token, providerResourceID string) string {
	if p := strings.TrimSuffix(strings.TrimSpace(providerResourceID), "/"); p != "" {
		return p
	}
	return objectPrefixForToken(token)
}
