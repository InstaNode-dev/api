//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"testing"
)

// allowQuotaBurn returns true only when E2E_ALLOW_QUOTA_BURN=true is explicitly set.
// Tests that send many provisions in a loop must call this guard —
// once real cloud providers are wired (Neon, Upstash, Atlas) each call has a cost.
// CI never sets this flag, so high-volume tests are skipped automatically.
func allowQuotaBurn(t *testing.T) {
	t.Helper()
	if os.Getenv("E2E_ALLOW_QUOTA_BURN") != "true" {
		t.Skip("skipping high-volume quota test (set E2E_ALLOW_QUOTA_BURN=true to run)")
	}
}

// TestE2E_Quota_ProvisionRateLimit verifies that after 5 provisions from the
// same IP, further provision attempts return the existing token rather than
// a new one (rate limit fail-open / reuse pattern).
func TestE2E_Quota_ProvisionRateLimit_ReturnsExistingToken(t *testing.T) {
	allowQuotaBurn(t) // provisions 6 cache resources — costs real cloud quota once providers are wired
	ip := uniqueIP(t)

	// Exhaust the 5-provision-per-day anonymous limit.
	tokens := make([]string, 5)
	for i := 0; i < 5; i++ {
		r := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
		if r.StatusCode == 503 {
			t.Skip("POST /cache/new: service not enabled (503)")
		}
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("provision %d: want 201, got %d\n%s", i+1, r.StatusCode, readBody(t, r))
		}
		var body provisionNewResponse
		decodeJSON(t, r, &body)
		tokens[i] = body.Token
	}

	// The 6th provision from the same IP should return an existing token.
	r6 := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if r6.StatusCode != http.StatusOK && r6.StatusCode != http.StatusCreated {
		t.Fatalf("6th provision: want 200 or 201, got %d\n%s", r6.StatusCode, readBody(t, r6))
	}
	var body6 provisionNewResponse
	decodeJSON(t, r6, &body6)

	// The returned token must be one of the previously issued ones.
	found := false
	for _, tok := range tokens {
		if tok == body6.Token {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("6th provision: got new token %q — expected an existing token from %v", body6.Token, tokens)
	}
}
