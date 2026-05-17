package storage

import "testing"

// prefixident_test.go — coverage tests for the token-truncation fix on the
// storage object-key prefix (BUGHUNT-REPORT-2026-05-17-round2.md, recurring
// pattern #1). These are INTERNAL tests (package storage) because the helpers
// are unexported.

// tokens that deliberately share their first 8 hex chars — the historical
// truncation collision.
const (
	prefixTokenA = "abc12345deadbeefcafef00d00112233"
	prefixTokenB = "abc12345111122223333444455556666"
)

// TestObjectPrefixForToken_FullToken — the core fix: the canonical object
// prefix is the FULL token, so two tokens sharing an 8-char prefix never share
// an object namespace (cross-tenant read in shared-key mode).
func TestObjectPrefixForToken_FullToken(t *testing.T) {
	if got := objectPrefixForToken(prefixTokenA); got != prefixTokenA {
		t.Errorf("objectPrefixForToken(tokenA) = %q; want the full token %q", got, prefixTokenA)
	}
	if objectPrefixForToken(prefixTokenA) == objectPrefixForToken(prefixTokenB) {
		t.Error("objectPrefixForToken collided for two tokens sharing an 8-char prefix — the bug must stay fixed")
	}
}

// TestLegacyObjectPrefixForToken_8CharSlice verifies the legacy probe form is
// exactly token[:8] for a long token and "" for short tokens. Under this
// legacy scheme tokenA and tokenB collide — that IS the bug being fixed.
func TestLegacyObjectPrefixForToken_8CharSlice(t *testing.T) {
	if got, want := legacyObjectPrefixForToken(prefixTokenA), prefixTokenA[:legacyObjectPrefixTokenLen]; got != want {
		t.Errorf("legacyObjectPrefixForToken(tokenA) = %q; want %q", got, want)
	}
	if legacyObjectPrefixForToken(prefixTokenA) != legacyObjectPrefixForToken(prefixTokenB) {
		t.Error("expected the legacy token[:8] scheme to collide for tokenA/tokenB (the bug being fixed)")
	}
	if got := legacyObjectPrefixForToken("abc"); got != "" {
		t.Errorf("legacyObjectPrefixForToken(shortToken) = %q; want \"\"", got)
	}
}

// TestResolveObjectPrefix_PrefersStoredPRID — a lifecycle op must use the
// prefix STORED at provision time, never re-derive it. The stored value is
// honoured whether or not it carries a trailing slash.
func TestResolveObjectPrefix_PrefersStoredPRID(t *testing.T) {
	if got := resolveObjectPrefix(prefixTokenA, prefixTokenA); got != prefixTokenA {
		t.Errorf("resolveObjectPrefix with stored PRID = %q; want %q", got, prefixTokenA)
	}
	// A slash-terminated stored value is normalised to slash-free.
	if got := resolveObjectPrefix(prefixTokenA, prefixTokenA+"/"); got != prefixTokenA {
		t.Errorf("resolveObjectPrefix must strip the trailing slash; got %q", got)
	}
}

// TestResolveObjectPrefix_LegacyFallback — the coverage test for the legacy
// path: a storage row with an empty provider_resource_id (provisioned before
// this fix shipped) must still resolve to a usable prefix, and the legacy
// token[:8] form must remain derivable for teardown. This test fails if a
// future change drops the empty-PRID fallback.
func TestResolveObjectPrefix_LegacyFallback(t *testing.T) {
	// Empty provider_resource_id → canonical full-token derivation.
	if got, want := resolveObjectPrefix(prefixTokenA, ""), objectPrefixForToken(prefixTokenA); got != want {
		t.Errorf("resolveObjectPrefix(tokenA, \"\") = %q; want full-token derivation %q", got, want)
	}
	// The legacy 8-char prefix for an old row stays derivable so Deprovision
	// can probe it.
	if got := legacyObjectPrefixForToken(prefixTokenA); got == "" {
		t.Error("legacy 8-char prefix must remain derivable for teardown of pre-fix rows")
	}
}

// TestMinioIdentifiers_DeriveFromPrefix verifies the IAM user/policy names are
// derived from the (full-token) prefix, so they never collide for distinct
// tokens.
func TestMinioIdentifiers_DeriveFromPrefix(t *testing.T) {
	a := objectPrefixForToken(prefixTokenA)
	b := objectPrefixForToken(prefixTokenB)
	if minioAccessKeyID(a) == minioAccessKeyID(b) {
		t.Error("minioAccessKeyID collided for two distinct full-token prefixes")
	}
	if minioPolicyName(a) == minioPolicyName(b) {
		t.Error("minioPolicyName collided for two distinct full-token prefixes")
	}
	if got, want := minioAccessKeyID(a), minioAccessKeyIDPrefix+prefixTokenA; got != want {
		t.Errorf("minioAccessKeyID = %q; want %q", got, want)
	}
}
