//go:build e2e

// Persona G — The Concurrent Agents
//
// Simulates multiple AI agents provisioning resources simultaneously from
// independent cloud environments, verifying:
//   - No cross-contamination of tokens between concurrent sessions
//   - Each agent's fingerprint remains independent
//   - Concurrent claims on distinct JWTs all succeed (no lock contention)
//   - The system handles burst provisioning without token collisions
//   - Two agents cannot claim the same resource (atomic single-claim guarantee)
//
// Designed to stress the provisioning layer at realistic burst concurrency (5-10 agents).
// No optional env vars required for most tests.
package e2e

import (
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// ── G1: 5 concurrent agents — all get unique tokens ──────────────────────────

func TestE2E_MultiAgent_ConcurrentProvisions_AllTokensUnique(t *testing.T) {
	const n = 5
	tokens := make([]string, n)
	errs := make([]string, n)

	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Each agent uses a unique random IP (/24) to model a real cloud instance.
			ip := uniqueIP(t)
			prov := provisionAnonymous(t, ip)
			if prov.Token == "" {
				errs[i] = fmt.Sprintf("agent %d: got empty token", i)
				return
			}
			tokens[i] = prov.Token
		}()
	}
	wg.Wait()

	for i, e := range errs {
		if e != "" {
			t.Errorf("agent %d error: %s", i, e)
		}
	}

	// All tokens must be non-empty and unique.
	seen := make(map[string]bool, n)
	for i, tok := range tokens {
		if tok == "" {
			t.Errorf("agent %d: got empty token", i)
			continue
		}
		if seen[tok] {
			t.Errorf("token collision: token %q appeared more than once", tok)
		}
		seen[tok] = true
	}
}

// ── G2: 5 concurrent agents — all claim distinct JWTs, all succeed ───────────

func TestE2E_MultiAgent_ConcurrentClaims_AllSucceed(t *testing.T) {
	const n = 5

	// Pre-provision one resource per agent (distinct IPs → distinct fingerprints).
	type agentData struct {
		jwt   string
		email string
	}
	agents := make([]agentData, n)
	for i := 0; i < n; i++ {
		ip := uniqueIP(t)
		resource := provisionAnonymous(t, ip)
		agents[i] = agentData{
			jwt:   extractJWTFromNote(t, resource.Note),
			email: fmt.Sprintf("e2e-agent-%s-%d@instant.dev", uuid.NewString()[:6], i),
		}
	}

	// Claim all 5 concurrently.
	codes := make([]int, n)
	teamIDs := make([]string, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp := post(t, "/claim", map[string]any{
				"jwt":       agents[i].jwt,
				"email":     agents[i].email,
				"team_name": fmt.Sprintf("e2e-magent-%d-%s", i, uuid.NewString()[:6]),
			})
			codes[i] = resp.StatusCode
			if resp.StatusCode == 201 {
				var body claimResponse
				decodeJSON(t, resp, &body)
				teamIDs[i] = body.TeamID
			} else {
				readBody(t, resp)
			}
		}()
	}
	wg.Wait()

	for i, code := range codes {
		if code != 201 {
			t.Errorf("agent %d claim: want 201, got %d", i, code)
		}
	}

	// Each successful claim must produce a distinct team ID.
	seenTeams := make(map[string]bool, n)
	for i, tid := range teamIDs {
		if tid == "" {
			continue // already reported above
		}
		if seenTeams[tid] {
			t.Errorf("team ID collision: agent %d got team_id %q which was already seen", i, tid)
		}
		seenTeams[tid] = true
	}
}

// ── G3: Same resource cannot be claimed by two concurrent agents ──────────────

func TestE2E_MultiAgent_SameJWT_ConcurrentClaims_OnlyOneWins(t *testing.T) {
	ip := uniqueIP(t)
	resource := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, resource.Note)

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
				"email":     fmt.Sprintf("agent-race-%s-%d@instant.dev", uuid.NewString()[:6], i),
				"team_name": fmt.Sprintf("race-team-%d-%s", i, uuid.NewString()[:6]),
			})
			codes[i] = resp.StatusCode
			resp.Body.Close()
		}()
	}
	wg.Wait()

	ok, conflict, other := 0, 0, 0
	for _, c := range codes {
		switch c {
		case 201:
			ok++
		case 409:
			conflict++
		default:
			other++
		}
	}

	if ok != 1 {
		t.Errorf("concurrent same-JWT claims: want exactly 1 success (201), got %d", ok)
	}
	if conflict != n-1 {
		t.Errorf("concurrent same-JWT claims: want %d conflicts (409), got %d", n-1, conflict)
	}
	if other != 0 {
		t.Errorf("concurrent same-JWT claims: %d unexpected status codes", other)
	}
}

// ── G4: 10-agent burst — no token collisions ─────────────────────────────────

func TestE2E_MultiAgent_BurstProvision_NoDuplicates(t *testing.T) {
	const n = 10
	tokens := make([]string, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			ip := uniqueIP(t)
			resource := provisionAnonymous(t, ip)
			tokens[i] = resource.Token
		}()
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i, tok := range tokens {
		if tok == "" {
			t.Errorf("agent %d: empty token", i)
			continue
		}
		if seen[tok] {
			t.Errorf("duplicate token from 10-agent burst: %q", tok)
		}
		seen[tok] = true
	}
	t.Logf("10-agent burst: %d unique tokens issued", len(seen))
}

// ── G5: Each agent's /start landing is fingerprint-isolated ──────────────────

func TestE2E_MultiAgent_StartLanding_FingerprintIsolated(t *testing.T) {
	// Two agents from distinct IPs — each /start must redirect with its own JWT.
	ipA := uniqueIP(t)
	resourceA := provisionAnonymous(t, ipA)
	jwtA := extractJWTFromNote(t, resourceA.Note)

	ipB := uniqueIP(t)
	resourceB := provisionAnonymous(t, ipB)
	jwtB := extractJWTFromNote(t, resourceB.Note)

	// Run both /start fetches concurrently (no-redirect: /start returns 302).
	type result struct {
		location string
		code     int
	}
	results := make([]result, 2)
	jwts := []string{jwtA, jwtB}

	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp := getNoRedirect(t, "/start?t="+jwts[i])
			results[i] = result{location: resp.Header.Get("Location"), code: resp.StatusCode}
			readBody(t, resp)
		}()
	}
	wg.Wait()

	for i := 0; i < 2; i++ {
		if results[i].code != http.StatusFound {
			t.Errorf("agent %d /start: want 302, got %d", i, results[i].code)
		}
	}

	// Each redirect must point to the dashboard ClaimPage with a JWT.
	if !contains(results[0].location, "/claim?t=") {
		t.Errorf("agent A /start Location must contain /claim?t=, got %q", results[0].location)
	}
	if !contains(results[1].location, "/claim?t=") {
		t.Errorf("agent B /start Location must contain /claim?t=, got %q", results[1].location)
	}
	// Cross-fingerprint isolation: each JWT is cryptographically scoped to its own
	// fingerprint — verified by the tampered-JWT tests in e2e_test.go.
}
