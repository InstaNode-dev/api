//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestE2E_RotateCredentials_Unauthenticated_Returns401 verifies that the
// credential rotation endpoint rejects unauthenticated requests with 401.
// This test does not require E2E_JWT_SECRET.
func TestE2E_RotateCredentials_Unauthenticated_Returns401(t *testing.T) {
	// Use a syntactically valid UUID that won't exist on the server.
	fakeToken := "00000000-0000-0000-0000-000000000099"

	resp := post(t, "/api/v1/resources/"+fakeToken+"/rotate-credentials", nil)
	defer resp.Body.Close()
	readBody(t, resp) // drain

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/resources/:id/rotate-credentials (no auth): want 401, got %d",
			resp.StatusCode)
	}
}

// TestE2E_RotateCredentials_Authenticated provisions a postgres resource,
// claims it, then rotates credentials — verifying that:
//   - POST /api/v1/resources/:token/rotate-credentials returns 200
//   - The response includes a connection_url
//   - The new URL is different from the original (password was rotated)
//
// Requires E2E_JWT_SECRET (skips automatically when not set).
// Run with: make test-e2e-full
func TestE2E_RotateCredentials_Authenticated(t *testing.T) {
	ip := uniqueIP(t)
	email := uniqueEmail()

	// Step 1: Provision a postgres resource to get a token + upgrade URL.
	dbResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	var db struct {
		OK            bool   `json:"ok"`
		Token         string `json:"token"`
		ConnectionURL string `json:"connection_url"`
		Note          string `json:"note"`
	}
	decodeJSON(t, dbResp, &db)
	if db.Token == "" {
		t.Fatalf("POST /db/new: got empty token")
	}
	originalURL := db.ConnectionURL

	// Step 2: Extract the onboarding JWT from the note field and claim the resource.
	onboardingJWT := extractJWTFromNote(t, db.Note)
	claimResp := post(t, "/claim", map[string]any{
		"jwt":   onboardingJWT,
		"email": email,
	})
	if claimResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)
	if claim.TeamID == "" {
		t.Fatalf("POST /claim: empty team_id in response")
	}

	// Step 3: Sign a session JWT using the real E2E_JWT_SECRET.
	// makeSessionJWT skips the test if E2E_JWT_SECRET is not set.
	sessionJWT := makeSessionJWT(t, claim.TeamID, email)

	// Step 4: Rotate credentials.
	rotResp := post(t, "/api/v1/resources/"+db.Token+"/rotate-credentials", nil,
		"Authorization", "Bearer "+sessionJWT)
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("POST rotate-credentials: want 200, got %d\n%s",
			rotResp.StatusCode, readBody(t, rotResp))
	}
	var rotBody struct {
		OK            bool   `json:"ok"`
		ConnectionURL string `json:"connection_url"`
	}
	decodeJSON(t, rotResp, &rotBody)

	if !rotBody.OK {
		t.Error("rotate-credentials: ok must be true")
	}
	if rotBody.ConnectionURL == "" {
		t.Fatal("rotate-credentials: response missing connection_url")
	}
	if rotBody.ConnectionURL == originalURL {
		t.Error("rotate-credentials: new URL is identical to original — password was not rotated")
	}
	t.Logf("credential rotation successful: URL changed (%d chars → %d chars)",
		len(originalURL), len(rotBody.ConnectionURL))
}
