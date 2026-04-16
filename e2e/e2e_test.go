//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// ─── 1. Infrastructure ────────────────────────────────────────────────────────

func TestE2E_Healthz_ReturnsOK(t *testing.T) {
	resp := get(t, "/healthz")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz: want 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	decodeJSON(t, resp, &body)

	if body["ok"] != true {
		t.Errorf("GET /healthz: want ok=true, got %v", body)
	}
	if body["service"] != "instant.dev" {
		t.Errorf("GET /healthz: want service=instant.dev, got %v", body["service"])
	}
}

func TestE2E_MetricsEndpoint_ReturnsPrometheusText(t *testing.T) {
	resp := get(t, "/metrics")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: want 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "# HELP") {
		t.Errorf("GET /metrics: expected Prometheus HELP lines, got: %.200s", body)
	}
}

// ─── 2. Rate Limiting ─────────────────────────────────────────────────────────

// TestE2E_ProvisionLimit_6thCallReturnsPreviousToken verifies that the 6th POST
// /cache/new from the same IP returns an existing token (fail-open deduplication),
// not a new one and not a 429. The dedup cap is shared across all service types.
func TestE2E_ProvisionLimit_6thCallReturnsPreviousToken(t *testing.T) {
	// All 6 requests must use the SAME /24 subnet to share one fingerprint.
	// Use a fixed subnet derived from a unique UUID suffix so parallel test
	// runs don't collide with each other.
	id := uuid.New()
	ip := fmt.Sprintf("172.16.%d.1", id[0]%254+1) // same /24 for all 6 calls below

	var seen []string
	for i := 0; i < 5; i++ {
		prov := provisionAnonymous(t, ip)
		seen = append(seen, prov.Token)
	}

	// 6th call — limit exceeded; must return an existing token, status 200.
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == http.StatusTooManyRequests {
		readBody(t, resp)
		t.Fatal("6th provision must not return 429 — should fail-open and return existing token")
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	existingSet := make(map[string]bool, len(seen))
	for _, tok := range seen {
		existingSet[tok] = true
	}

	if !existingSet[body.Token] {
		t.Errorf("6th provision must return one of the existing tokens; got new token %q", body.Token)
	}
}

// ─── 3. Onboarding Funnel ─────────────────────────────────────────────────────

func TestE2E_StartLanding_NoToken_Returns400(t *testing.T) {
	resp := get(t, "/start")
	readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /start (no token): want 400, got %d", resp.StatusCode)
	}
}

func TestE2E_StartLanding_TamperedJWT_ReturnsError(t *testing.T) {
	resp := get(t, "/start?t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWNrIn0.badsig")
	readBody(t, resp)

	// The server returns 400 (bad request) or 401 (unauthorized) for a tampered JWT.
	// Either is correct — the important thing is it's not 200.
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized:
		// OK
	default:
		t.Errorf("GET /start (tampered JWT): want 400 or 401, got %d", resp.StatusCode)
	}
}

func TestE2E_StartLanding_ValidJWT_Returns302Redirect(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	jwt := extractJWTFromNote(t, prov.Note)

	// /start now redirects to the dashboard ClaimPage — use no-redirect client.
	resp := getNoRedirect(t, "/start?t="+jwt)
	readBody(t, resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /start?t=<jwt>: want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/claim?t=") {
		t.Errorf("GET /start: Location must contain /claim?t=, got %q", loc)
	}
}

func TestE2E_Claim_Success_Returns201WithTeamID(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, prov.Note)

	resp := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"team_name": "e2e-team-" + uuid.NewString()[:6],
		"email":     uniqueEmail(),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /claim: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body claimResponse
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("POST /claim: ok must be true")
	}
	if body.TeamID == "" {
		t.Error("POST /claim: team_id must be present in response")
	}
	if _, err := uuid.Parse(body.TeamID); err != nil {
		t.Errorf("POST /claim: team_id %q must be a valid UUID", body.TeamID)
	}
}

func TestE2E_Claim_MissingEmail_Returns400(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, prov.Note)

	resp := post(t, "/claim", map[string]any{
		"jwt": jwt,
		// email intentionally omitted
	})
	readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /claim (no email): want 400, got %d", resp.StatusCode)
	}
}

func TestE2E_Claim_MissingJWT_Returns400(t *testing.T) {
	resp := post(t, "/claim", map[string]any{
		"email": uniqueEmail(),
	})
	readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("POST /claim (no jwt): want 400, got %d", resp.StatusCode)
	}
}

func TestE2E_Claim_DoubleClaim_Returns409(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, prov.Note)
	email := uniqueEmail()

	body1 := map[string]any{"jwt": jwt, "email": email, "team_name": "e2e-dupe-" + uuid.NewString()[:6]}
	resp1 := post(t, "/claim", body1)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("first POST /claim: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	readBody(t, resp1)

	// Second claim with the same JWT must return 409.
	resp2 := post(t, "/claim", body1)
	readBody(t, resp2)

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second POST /claim (same JWT): want 409 Conflict, got %d", resp2.StatusCode)
	}
}

// ─── 4. Concurrency ──────────────────────────────────────────────────────────

// TestE2E_ConcurrentProvisions_NoDuplicateTokens provisions 10 resources from 10
// distinct IPs concurrently and verifies every token is unique.
func TestE2E_ConcurrentProvisions_NoDuplicateTokens(t *testing.T) {
	const n = 10
	tokens := make([]string, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Each goroutine uses a distinct /24 to avoid hitting the provisioning cap.
			ip := fmt.Sprintf("100.64.%d.1", i+1)
			prov := provisionAnonymous(t, ip)
			tokens[i] = prov.Token
		}()
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for _, tok := range tokens {
		if tok == "" {
			t.Error("got empty token from concurrent provision")
			continue
		}
		if seen[tok] {
			t.Errorf("duplicate token detected: %q", tok)
		}
		seen[tok] = true
	}
}

// TestE2E_ConcurrentClaims_OnlyOneSucceeds provisions one resource and fires 5
// concurrent /claim requests with the same JWT — exactly one must succeed (201),
// the rest must be 409.
func TestE2E_ConcurrentClaims_OnlyOneSucceeds(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, prov.Note)

	const n = 5
	codes := make([]int, n)
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp := post(t, "/claim", map[string]any{
				"jwt":       jwt,
				"email":     fmt.Sprintf("race-%s-%d@instant.dev", uuid.NewString()[:8], i),
				"team_name": fmt.Sprintf("e2e-race-%d-%s", i, uuid.NewString()[:6]),
			})
			codes[i] = resp.StatusCode
			resp.Body.Close()
		}()
	}
	wg.Wait()

	var ok, conflict, other int
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			ok++
		case http.StatusConflict:
			conflict++
		default:
			other++
			t.Logf("unexpected status: %d", c)
		}
	}

	if ok != 1 {
		t.Errorf("concurrent claims: want exactly 1 success (201), got %d", ok)
	}
	if conflict != n-1 {
		t.Errorf("concurrent claims: want %d conflicts (409), got %d", n-1, conflict)
	}
	if other != 0 {
		t.Errorf("concurrent claims: got %d unexpected status codes", other)
	}
}

// ─── 5. Full User Journey ─────────────────────────────────────────────────────

// TestE2E_FullUserJourney_AnonymousToConverted is the end-to-end scenario for
// the agentic onboarding funnel:
//
//  1. Agent provisions a cache resource (no account)  → token + upgrade URL
//  2. Developer follows the upgrade URL to /start      → 302 → dashboard ClaimPage
//  3. Developer POSTs to /claim                        → 201 with team_id
//  4. Developer tries to claim again (replay attack)   → 409 Conflict
func TestE2E_FullUserJourney_AnonymousToConverted(t *testing.T) {
	ip := uniqueIP(t)
	email := uniqueEmail()

	// Step 1: Provision
	t.Log("Step 1: provisioning anonymous resource...")
	prov := provisionAnonymous(t, ip)
	t.Logf("  token=%s tier=%s", prov.Token, prov.Tier)

	if prov.Tier != "anonymous" {
		t.Errorf("step 1: expected anonymous tier, got %q", prov.Tier)
	}

	// Step 2: Follow upgrade URL → /start redirects to dashboard ClaimPage
	t.Log("Step 2: following upgrade URL to /start...")
	jwt := extractJWTFromNote(t, prov.Note)
	resp2 := getNoRedirect(t, "/start?t="+jwt)
	if resp2.StatusCode != http.StatusFound {
		t.Fatalf("step 2: GET /start?t=<jwt> want 302, got %d\n%s", resp2.StatusCode, readBody(t, resp2))
	}
	loc2 := resp2.Header.Get("Location")
	if !strings.Contains(loc2, "/claim?t=") {
		t.Errorf("step 2: Location must contain /claim?t=, got %q", loc2)
	}
	readBody(t, resp2)
	t.Logf("step 2: /start redirected to %s", loc2)

	// Step 3: Claim the account
	t.Log("Step 3: claiming account...")
	resp3 := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     email,
		"team_name": "e2e-journey-" + uuid.NewString()[:6],
	})
	if resp3.StatusCode != http.StatusCreated {
		t.Fatalf("step 3: POST /claim want 201, got %d\n%s", resp3.StatusCode, readBody(t, resp3))
	}
	var claim claimResponse
	decodeJSON(t, resp3, &claim)

	if claim.TeamID == "" {
		t.Error("step 3: team_id must be present after successful claim")
	}
	t.Logf("  team_id=%s", claim.TeamID)

	// Step 4: Replay attack — second claim must fail
	t.Log("Step 4: replay attack (second claim with same JWT)...")
	resp4 := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     uniqueEmail(),
		"team_name": "e2e-replay-" + uuid.NewString()[:6],
	})
	readBody(t, resp4)

	if resp4.StatusCode != http.StatusConflict {
		t.Errorf("step 4: replay attack must return 409 Conflict, got %d", resp4.StatusCode)
	}

	t.Log("Full journey passed.")
}

// ─── 6. Auth-based plan limits ────────────────────────────────────────────────

// TestE2E_OptionalAuth_InvalidBearerToken_FallsBackToAnonymous verifies that
// a malformed Authorization header does NOT block provisioning — the server
// must fall back to anonymous mode transparently.
func TestE2E_OptionalAuth_InvalidBearerToken_FallsBackToAnonymous(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil,
		"X-Forwarded-For", ip,
		"Authorization", "Bearer not-a-valid-jwt-at-all",
	)
	if resp.StatusCode == 503 {
		t.Skip("POST /cache/new: service not enabled (503) — skip")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /cache/new with invalid bearer token: want 201, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Tier != "anonymous" {
		t.Errorf("invalid bearer token must fall back to anonymous tier, got %q", body.Tier)
	}
	if body.Token == "" {
		t.Error("token must be provisioned even with invalid bearer token")
	}
}

// TestE2E_OptionalAuth_NoBearerToken_AnonymousPath verifies the standard
// anonymous path is unaffected by the OptionalAuth middleware addition.
func TestE2E_OptionalAuth_NoBearerToken_AnonymousPath(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		t.Skip("POST /cache/new: service not enabled (503) — skip")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /cache/new without auth header: want 201, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Tier != "anonymous" {
		t.Errorf("unauthenticated provision must produce anonymous tier, got %q", body.Tier)
	}
}
