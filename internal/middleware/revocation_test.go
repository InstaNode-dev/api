package middleware

// revocation_test.go — regression tests for JTI revocation key consistency (A03).
//
// The critical invariant: handlers.RevokedJTIKey and middleware.revokedJTIKey
// must produce identical output. If they drift, a revoked JTI stored by the
// logout handler will never be found by RequireAuth, silently breaking
// server-side logout.
//
// Since the middleware package cannot import handlers (package cycle), both
// packages define their own copy of the key format under the same named
// constant. This test guards the middleware half; auth_logout_test.go guards
// the handler half.

import (
	"context"
	"testing"
)

// TestRevokedJTIKey_Format asserts that revokedJTIKey produces the canonical
// "session.revoked:<jti>" format. Must match handlers.RevokedJTIKey exactly.
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
		got := revokedJTIKey(tc.jti)
		if got != tc.want {
			t.Errorf("middleware.revokedJTIKey(%q) = %q, want %q — must match handlers.RevokedJTIKey",
				tc.jti, got, tc.want)
		}
	}
}

// TestIsJTIRevoked_NilRedis asserts that IsJTIRevoked returns (false, nil)
// when revocationRDB is nil (fail-open per CLAUDE.md convention 1). This
// is safe because nil is the startup value before SetRevocationDB is called
// and also the value in tests that don't wire Redis.
func TestIsJTIRevoked_NilRedis(t *testing.T) {
	prev := revocationRDB
	revocationRDB = nil
	defer func() { revocationRDB = prev }()

	revoked, err := IsJTIRevoked(context.Background(), "any-jti")
	if err != nil {
		t.Errorf("IsJTIRevoked with nil rdb returned error %v, want nil (fail-open)", err)
	}
	if revoked {
		t.Error("IsJTIRevoked with nil rdb returned revoked=true, want false (fail-open)")
	}
}

// TestIsJTIRevoked_EmptyJTI asserts that an empty JTI is always treated as
// not-revoked without hitting Redis. Tokens without jti cannot be individually
// revoked (they're old tokens); failing open here is correct.
func TestIsJTIRevoked_EmptyJTI(t *testing.T) {
	prev := revocationRDB
	revocationRDB = nil // ensure any accidental Redis call panics immediately
	defer func() { revocationRDB = prev }()

	revoked, err := IsJTIRevoked(context.Background(), "")
	if err != nil {
		t.Errorf("IsJTIRevoked with empty jti returned error %v, want nil", err)
	}
	if revoked {
		t.Error("IsJTIRevoked with empty jti returned revoked=true, want false")
	}
}

// TestRevokedJTIKeyPrefix_Constant asserts the revokedJTIKeyPrefix constant
// value. This is the golden-string that both handler and middleware must agree
// on. Any change to this test REQUIRES a simultaneous change in
// auth_logout_test.go and a Redis migration plan.
func TestRevokedJTIKeyPrefix_Constant(t *testing.T) {
	const wantPrefix = "session.revoked"
	if revokedJTIKeyPrefix != wantPrefix {
		t.Errorf("middleware.revokedJTIKeyPrefix = %q, want %q — must match handlers constant",
			revokedJTIKeyPrefix, wantPrefix)
	}
}
