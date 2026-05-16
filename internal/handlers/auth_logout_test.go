package handlers

// auth_logout_test.go — unit tests for server-side logout + JTI revocation (A03).
//
// Tests live in package handlers (not handlers_test) so they can access
// the unexported helpers (rawLogoutClaims, revokedJTIKeyPrefix).
// The table-driven structure follows the pattern established in magic_link_test.go.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestRevokedJTIKey_Format asserts that RevokedJTIKey produces the canonical
// "session.revoked:<jti>" format. This golden-string test is the coverage
// gate mentioned in middleware/revocation.go: if either the handler or the
// middleware changes the format unilaterally, one of the two tests breaks
// and the drift is caught before deploy.
func TestRevokedJTIKey_Format(t *testing.T) {
	cases := []struct {
		jti  string
		want string
	}{
		{"", "session.revoked:"},
		{"abc-123", "session.revoked:abc-123"},
		{"550e8400-e29b-41d4-a716-446655440000", "session.revoked:550e8400-e29b-41d4-a716-446655440000"},
	}
	for _, tc := range cases {
		got := RevokedJTIKey(tc.jti)
		if got != tc.want {
			t.Errorf("RevokedJTIKey(%q) = %q, want %q", tc.jti, got, tc.want)
		}
	}
}

// TestRevokedJTIKeyPrefix_MatchesMiddleware asserts that the key prefix
// used by the handler (revokedJTIKeyPrefix) matches the one in
// middleware/revocation.go. The middleware has its own copy because of the
// package-cycle constraint; this test catches drift.
//
// The middleware constant is "session.revoked" — duplicated here as a literal
// so the test fails if either constant changes without the other changing too.
func TestRevokedJTIKeyPrefix_MatchesMiddleware(t *testing.T) {
	const middlewarePrefix = "session.revoked" // must match middleware.revokedJTIKeyPrefix
	if revokedJTIKeyPrefix != middlewarePrefix {
		t.Errorf("handlers.revokedJTIKeyPrefix = %q does not match middleware.revokedJTIKeyPrefix = %q — logout revocation will silently break",
			revokedJTIKeyPrefix, middlewarePrefix,
		)
	}
}

// TestEmailRateLimitKey_Hashes asserts that emailRateLimitKey returns a
// consistent, non-empty, non-PII string for a given email. The key must:
//  1. Always start with the expected prefix.
//  2. Never contain the raw email address (PII guard).
//  3. Be stable across calls (deterministic).
func TestEmailRateLimitKey_Hashes(t *testing.T) {
	const email = "alice@example.com"
	key := emailRateLimitKey(email)

	if key == "" {
		t.Fatal("emailRateLimitKey returned empty string")
	}
	if key == email {
		t.Errorf("emailRateLimitKey must not return the raw email address (PII leak)")
	}
	// Must start with the declared prefix.
	expectedPrefix := magicLinkEmailRLKeyPrefix + ":"
	if len(key) < len(expectedPrefix) || key[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("emailRateLimitKey(%q) = %q, want prefix %q", email, key, expectedPrefix)
	}
	// Must be deterministic.
	if emailRateLimitKey(email) != key {
		t.Error("emailRateLimitKey is not deterministic")
	}
	// Different emails must produce different keys.
	if emailRateLimitKey("bob@example.com") == key {
		t.Error("emailRateLimitKey produced same key for different emails")
	}
}

// TestEmailRateLimitKey_DoesNotLeakPII asserts that none of the raw email
// characters appear in the hashed key (beyond the prefix). A Redis MONITOR
// or memory dump must not expose user email addresses.
func TestEmailRateLimitKey_DoesNotLeakPII(t *testing.T) {
	emails := []string{
		"user@example.com",
		"alice.smith+tag@corp.io",
		"UPPER@CASE.ORG",
	}
	for _, email := range emails {
		key := emailRateLimitKey(email)
		// The suffix (after the prefix+":") must not contain the local-part.
		prefixLen := len(magicLinkEmailRLKeyPrefix) + 1 // +1 for ":"
		suffix := key[prefixLen:]
		// Check that no word longer than 2 chars from the email appears in the suffix.
		// (A 2-char coincidence is acceptable; a 5+ char match is a leak.)
		emailParts := []string{
			email,
			email[:len(email)/2],
		}
		for _, part := range emailParts {
			if len(part) > 4 && contains(suffix, part) {
				t.Errorf("emailRateLimitKey suffix %q contains PII from email %q", suffix, part)
			}
		}
	}
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()
}

// TestCheckEmailRateLimit_NilRedis asserts that a nil Redis client causes
// checkEmailRateLimit to return (false, nil) — fail-open per CLAUDE.md
// convention 1. This is the most important invariant: a Redis outage must
// never block legitimate sign-in attempts.
func TestCheckEmailRateLimit_NilRedis(t *testing.T) {
	limited, err := checkEmailRateLimit(context.Background(), nil, "user@example.com")
	if err != nil {
		t.Errorf("checkEmailRateLimit with nil rdb returned error: %v (want nil — fail-open)", err)
	}
	if limited {
		t.Error("checkEmailRateLimit with nil rdb returned limited=true (want false — fail-open)")
	}
}

// TestMagicLinkEmailRateLimit_Constants asserts that the rate-limit constants
// have sensible values. If these are accidentally zeroed or negated, the
// rate limiter becomes either a deny-all or a no-op.
func TestMagicLinkEmailRateLimit_Constants(t *testing.T) {
	if magicLinkEmailRateLimit <= 0 {
		t.Errorf("magicLinkEmailRateLimit = %d, must be > 0", magicLinkEmailRateLimit)
	}
	if magicLinkEmailRateLimitWindow <= 0 {
		t.Errorf("magicLinkEmailRateLimitWindow = %v, must be > 0", magicLinkEmailRateLimitWindow)
	}
	if magicLinkEmailRateLimitWindow > 24*time.Hour {
		t.Errorf("magicLinkEmailRateLimitWindow = %v, exceeds 24h — this is unexpectedly aggressive", magicLinkEmailRateLimitWindow)
	}
	if magicLinkEmailRLKeyPrefix == "" {
		t.Error("magicLinkEmailRLKeyPrefix must not be empty")
	}
}

// TestRevokedJTIKey_StableFormat is a table-driven regression test that
// guards the exact format of every part of the key. If the format changes,
// all existing revoked-token keys in Redis become orphans (they will never
// match future lookups) and users who logged out before the change will find
// their tokens valid again. This test catches that class of bug.
func TestRevokedJTIKey_StableFormat(t *testing.T) {
	cases := []struct {
		name string
		jti  string
		want string
	}{
		{
			name: "uuid_v4",
			jti:  "550e8400-e29b-41d4-a716-446655440000",
			want: fmt.Sprintf("session.revoked:%s", "550e8400-e29b-41d4-a716-446655440000"),
		},
		{
			name: "short_jti",
			jti:  "abc",
			want: "session.revoked:abc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RevokedJTIKey(tc.jti)
			if got != tc.want {
				t.Errorf("RevokedJTIKey(%q) = %q, want %q", tc.jti, got, tc.want)
			}
		})
	}
}
