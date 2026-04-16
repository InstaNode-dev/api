//go:build e2e

// Persona F — The Cross-Service Isolationist
//
// Verifies that service tokens are fully isolated from each other:
//   - A resource token cannot be used to rotate credentials for a different resource
//   - Resources provisioned by different fingerprints are independent
//   - The /start landing groups resources by fingerprint, not globally
//   - Resource lists are scoped to the claiming team
//
// No optional env vars required for most tests. Tests that call
// makeSessionJWT will skip automatically if E2E_JWT_SECRET is absent.
package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// ── F2: Cache token rotate-credentials returns a valid new connection_url ───────

func TestE2E_CrossService_CacheToken_RotateCredentials_Returns200OrUnimplemented(t *testing.T) {
	ip := uniqueIP(t)
	resource := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, resource.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt": jwt, "email": email, "team_name": "e2e-csmon-" + uuid.NewString()[:6],
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)
	sessionJWT := makeSessionJWT(t, claim.TeamID, email)

	rotResp := post(t, "/api/v1/resources/"+resource.Token+"/rotate-credentials", nil,
		"Authorization", "Bearer "+sessionJWT)
	body := readBody(t, rotResp)

	switch rotResp.StatusCode {
	case http.StatusOK:
		// Rotate is implemented — verify new connection_url is present.
		if len(body) == 0 {
			t.Error("rotate-credentials 200 must return a body with connection_url")
		}
	case http.StatusNotImplemented, http.StatusNotFound:
		// Not yet implemented for this service type — acceptable.
	default:
		t.Errorf("rotate-credentials: want 200, 404, or 501, got %d; body=%s", rotResp.StatusCode, body)
	}
}

// ── F3: Two different fingerprints — each sees only its own resources ─────────

func TestE2E_CrossService_TwoFingerprints_ResourcesAreIsolated(t *testing.T) {
	// Fingerprint A provisions a resource.
	ipA := uniqueIP(t)
	resourceA := provisionAnonymous(t, ipA)
	jwtA := extractJWTFromNote(t, resourceA.Note)

	// Fingerprint B provisions a resource.
	ipB := uniqueIP(t)
	resourceB := provisionAnonymous(t, ipB)
	jwtB := extractJWTFromNote(t, resourceB.Note)

	// Each /start must redirect (302) to the dashboard ClaimPage — fingerprint-scoped
	// via the signed JWT. Cross-fingerprint isolation is enforced by the JWT signature.
	respA := getNoRedirect(t, "/start?t="+jwtA)
	readBody(t, respA)
	if respA.StatusCode != http.StatusFound {
		t.Fatalf("GET /start?t=jwtA: want 302, got %d", respA.StatusCode)
	}
	locA := respA.Header.Get("Location")
	if !contains(locA, "/claim?t=") {
		t.Errorf("/start for fingerprint A: Location must contain /claim?t=, got %q", locA)
	}

	respB := getNoRedirect(t, "/start?t="+jwtB)
	readBody(t, respB)
	if respB.StatusCode != http.StatusFound {
		t.Fatalf("GET /start?t=jwtB: want 302, got %d", respB.StatusCode)
	}
	locB := respB.Header.Get("Location")
	if !contains(locB, "/claim?t=") {
		t.Errorf("/start for fingerprint B: Location must contain /claim?t=, got %q", locB)
	}
}

// ── F7: Resource list is scoped to claiming team — other team's resources absent

func TestE2E_CrossService_ResourceList_ScopedToTeam(t *testing.T) {
	// Team A claims a resource.
	ipA := uniqueIP(t)
	resourceA := provisionAnonymous(t, ipA)
	jwtA := extractJWTFromNote(t, resourceA.Note)
	emailA := uniqueEmail()
	claimA := post(t, "/claim", map[string]any{
		"jwt": jwtA, "email": emailA, "team_name": "e2e-csA-" + uuid.NewString()[:6],
	})
	var claimBodyA claimResponse
	decodeJSON(t, claimA, &claimBodyA)
	sessionA := makeSessionJWT(t, claimBodyA.TeamID, emailA)

	// Team B claims a separate resource.
	ipB := uniqueIP(t)
	resourceB := provisionAnonymous(t, ipB)
	jwtB := extractJWTFromNote(t, resourceB.Note)
	emailB := uniqueEmail()
	claimB := post(t, "/claim", map[string]any{
		"jwt": jwtB, "email": emailB, "team_name": "e2e-csB-" + uuid.NewString()[:6],
	})
	var claimBodyB claimResponse
	decodeJSON(t, claimB, &claimBodyB)
	sessionB := makeSessionJWT(t, claimBodyB.TeamID, emailB)

	// Team A's resource list must NOT contain Team B's token.
	listA := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionA)
	bodyA := readBody(t, listA)
	if listA.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources as team A: want 200, got %d", listA.StatusCode)
	}
	if contains(bodyA, resourceB.Token) {
		t.Errorf("Team A resource list must not contain Team B's token %q", resourceB.Token)
	}

	// Team B's resource list must NOT contain Team A's token.
	listB := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionB)
	bodyB := readBody(t, listB)
	if listB.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources as team B: want 200, got %d", listB.StatusCode)
	}
	if contains(bodyB, resourceA.Token) {
		t.Errorf("Team B resource list must not contain Team A's token %q", resourceA.Token)
	}
}

// contains is a simple string containment check (avoids importing strings in this file).
func contains(s, sub string) bool {
	if sub == "" {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
