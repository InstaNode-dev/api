package middleware

// idempotency_mutable_cache_test.go — BUG-API-238 regression.
//
// The shouldCacheResponse helper governs whether a non-5xx response is
// written to the explicit-key (24h) or fingerprint (120s) idempotency
// cache. Most 4xx responses cache; a small allowlist of "mutable" error
// codes (currently free_tier_recycle_requires_claim) MUST skip the cache
// so a user-side action (e.g. claiming with email) that clears the gate
// is honoured on the agent's next retry of the same Idempotency-Key.
//
// Whitebox test (same package) so we can exercise shouldCacheResponse
// directly without spinning a Redis fake.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShouldCacheResponse_DefaultBehaviour covers the pre-fix contract:
// success caches, stable 4xx caches, non-JSON caches.
func TestShouldCacheResponse_DefaultBehaviour(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     []byte
		ct       string
		wantCache bool
	}{
		{"200 OK json", 200, []byte(`{"ok":true}`), "application/json", true},
		{"201 Created json", 201, []byte(`{"ok":true}`), "application/json", true},
		{"400 with quota_exceeded error caches (stable)", 402, []byte(`{"error":"quota_exceeded"}`), "application/json", true},
		{"400 with idempotency_key_conflict caches (stable)", 409, []byte(`{"error":"idempotency_key_conflict"}`), "application/json", true},
		{"4xx with provision_limit_reached caches (calendar boundary)", 429, []byte(`{"error":"provision_limit_reached"}`), "application/json", true},
		{"non-JSON 4xx caches (no error field to inspect)", 400, []byte(`<html>oops</html>`), "text/html", true},
		{"empty body caches (no error field to inspect)", 400, []byte(``), "application/json", true},
		{"malformed JSON caches (defer to default)", 400, []byte(`{not-json}`), "application/json", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldCacheResponse(tc.status, tc.body, tc.ct)
			assert.Equal(t, tc.wantCache, got,
				"shouldCacheResponse(status=%d, ct=%q) = %v; want %v", tc.status, tc.ct, got, tc.wantCache)
		})
	}
}

// TestShouldCacheResponse_MutableErrorsSkipCache is the BUG-API-238
// regression: every entry in the mutableErrorCodes map must return
// false from shouldCacheResponse so the agent gets fresh handler output
// on the next retry.
func TestShouldCacheResponse_MutableErrorsSkipCache(t *testing.T) {
	require.NotEmpty(t, mutableErrorCodes,
		"BUG-API-238: mutableErrorCodes must list at least free_tier_recycle_requires_claim")

	// Sanity: the canonical case is registered.
	_, ok := mutableErrorCodes["free_tier_recycle_requires_claim"]
	require.True(t, ok,
		"BUG-API-238: free_tier_recycle_requires_claim must be in mutableErrorCodes")

	// Iterate the live registry (rule 18: registry-iterating regression
	// test, not a hand-typed list) so any future addition is automatically
	// covered.
	for code := range mutableErrorCodes {
		t.Run(code, func(t *testing.T) {
			// Recycle gate returns 402 with claim_url etc. — exercise the
			// representative case.
			body := []byte(`{"ok":false,"error":"` + code + `","claim_url":"https://instanode.dev/claim"}`)
			got := shouldCacheResponse(402, body, "application/json")
			assert.False(t, got,
				"BUG-API-238: 402 with error=%q must skip the cache; got cache=true", code)
		})
	}
}

// TestIdempotency_RecycleGate402_SourceAssertion is a static-source
// belt-and-suspenders: the call sites in both idempotency branches
// (explicit + fingerprint) must invoke shouldCacheResponse before
// writing. Without both wires the fix is half-applied (only one of
// the two cache paths bypasses) — exactly the rule-16 modal failure
// mode the agent-reliability rules call out.
func TestIdempotency_RecycleGate402_SourceAssertion(t *testing.T) {
	src, err := os.ReadFile("idempotency.go")
	require.NoError(t, err)
	body := string(src)

	// Both branches must call shouldCacheResponse. Count >= 2 so we
	// catch the case where someone deletes one of the two call sites.
	assert.GreaterOrEqual(t, strings.Count(body, "shouldCacheResponse("), 2,
		"BUG-API-238: shouldCacheResponse must be invoked on BOTH explicit and fingerprint cache-write paths (rule 16 — two emitters of one bug)")

	// The mutable list must reference the canonical error code by string
	// so a future refactor that renames the constant (and forgets the
	// map key) is caught by grep.
	assert.Contains(t, body, `"free_tier_recycle_requires_claim"`,
		"BUG-API-238: mutableErrorCodes must reference free_tier_recycle_requires_claim by string")
}
