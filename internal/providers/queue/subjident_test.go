package queue

// subjident_test.go — coverage tests for the NATS SubjectPrefix derivation
// (P1-W4-04). The headline regression test asserts that two tokens which
// COLLIDE on their first 8 hex characters produce DISTINCT subject prefixes —
// the exact cross-tenant-pub/sub class the old token[:8] truncation caused on
// the shared no-auth NATS backend.

import "testing"

// TestCanonicalSubjectPrefix_NoEightCharCollision is the P1-W4-04 regression
// test. Two distinct tokens that share their first 8 hex characters MUST land
// in different subject namespaces — on the shared no-auth NATS backend the
// SubjectPrefix is the only tenant-isolation boundary.
func TestCanonicalSubjectPrefix_NoEightCharCollision(t *testing.T) {
	// Both tokens share the first 8 characters "a1b2c3d4" — the old
	// token[:8] truncation collapsed both onto the prefix "a1b2c3d4.".
	tokenA := "a1b2c3d4-1111-1111-1111-111111111111"
	tokenB := "a1b2c3d4-2222-2222-2222-222222222222"

	prefixA := canonicalSubjectPrefix(tokenA)
	prefixB := canonicalSubjectPrefix(tokenB)

	if prefixA == prefixB {
		t.Fatalf("8-char-colliding tokens produced the SAME subject prefix %q — "+
			"cross-tenant pub/sub on shared NATS (P1-W4-04 regression)", prefixA)
	}

	// Sanity: the legacy truncation WOULD have collided — proving the test
	// exercises a real collision pair and not two trivially-different tokens.
	if legacySubjectPrefix(tokenA) != legacySubjectPrefix(tokenB) {
		t.Fatalf("test setup error: tokens do not collide under the legacy "+
			"token[:8] scheme (%q vs %q) — pick a real collision pair",
			legacySubjectPrefix(tokenA), legacySubjectPrefix(tokenB))
	}
}

// TestCanonicalSubjectPrefix_FullTokenAndDashStripped asserts the canonical
// prefix is derived from the FULL token with dashes stripped, and is a single
// valid NATS subject token (no '.', '*', '>').
func TestCanonicalSubjectPrefix_FullTokenAndDashStripped(t *testing.T) {
	token := "abcd1234-ef56-7890-abcd-ef1234567890"
	got := canonicalSubjectPrefix(token)
	want := "abcd1234ef567890abcdef1234567890" + subjectPrefixSep
	if got != want {
		t.Fatalf("canonicalSubjectPrefix(%q) = %q, want %q", token, got, want)
	}
	// Body (everything before the trailing separator) must contain no NATS
	// subject metacharacters.
	body := got[:len(got)-len(subjectPrefixSep)]
	for _, c := range body {
		if c == '.' || c == '*' || c == '>' || c == '-' {
			t.Fatalf("canonical prefix body %q contains an invalid NATS subject-token char %q", body, c)
		}
	}
}

// TestLegacySubjectPrefix_ShortTokenEmpty verifies legacySubjectPrefix returns
// "" for a token too short to ever have been truncated — the canonical prefix
// already equals the legacy one, so no fallback probe is needed.
func TestLegacySubjectPrefix_ShortTokenEmpty(t *testing.T) {
	if got := legacySubjectPrefix("abc"); got != "" {
		t.Fatalf("legacySubjectPrefix(short) = %q, want \"\"", got)
	}
	if got := legacySubjectPrefix("12345678"); got != "" {
		t.Fatalf("legacySubjectPrefix(exactly-8) = %q, want \"\" (canonical == legacy)", got)
	}
}

// TestResolveSubjectPrefix_PrefersProviderResourceID verifies resolveSubjectPrefix
// returns the stamped provider_resource_id when present, and the canonical
// full-token derivation when it is empty.
func TestResolveSubjectPrefix_PrefersProviderResourceID(t *testing.T) {
	token := "a1b2c3d4-1111-1111-1111-111111111111"

	if got := resolveSubjectPrefix(token, "stamped.prefix."); got != "stamped.prefix." {
		t.Fatalf("resolveSubjectPrefix with PRID = %q, want stamped value", got)
	}
	if got := resolveSubjectPrefix(token, ""); got != canonicalSubjectPrefix(token) {
		t.Fatalf("resolveSubjectPrefix without PRID = %q, want canonical %q",
			got, canonicalSubjectPrefix(token))
	}
}
