//go:build e2e

// Auth Flow — S4 from the full-system test plan.
//
// Covers the complete claim → session → auth/me lifecycle:
//   S4.1  Provision cache → extract JWT → POST /claim → 201, team_id + user_id
//   S4.2  GET /auth/me with valid session JWT → tier=hobby, email matches
//   S4.3  GET /auth/me without Authorization → 401
//   S4.4  GET /auth/me with malformed JWT → 401
//   S4.5  POST /claim same JWT twice (concurrent) → exactly one 201, one 409
//   S4.6  POST /claim without email → 400 or 422
//   S4.7  POST /claim with foreign JWT (not signed by this server) → 400 or 422
//   S4.8  After claim: GET /api/v1/resources includes the claimed token
//
// Requires E2E_JWT_SECRET for S4.2 and S4.8 (session JWT construction).
package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ── S4.1: Claim provisions a team and returns team_id + user_id ─────────────

func TestE2E_AuthFlow_Claim_Returns201WithTeamAndUser(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	resp := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": email,
	})
	if resp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body claimResponse
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("claim response ok must be true")
	}
	if body.TeamID == "" {
		t.Error("team_id must not be empty")
	}
	if _, err := uuid.Parse(body.TeamID); err != nil {
		t.Errorf("team_id must be a valid UUID, got %q", body.TeamID)
	}
	if body.UserID == "" {
		t.Error("user_id must not be empty")
	}
	if _, err := uuid.Parse(body.UserID); err != nil {
		t.Errorf("user_id must be a valid UUID, got %q", body.UserID)
	}
}

// ── S4.2: GET /auth/me with valid session JWT → tier=hobby, email matches ────

func TestE2E_AuthFlow_AuthMe_ValidSession_ReturnsTierAndEmail(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": email,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	me := getAuthMe(t, sessionJWT)

	if me["tier"] != "hobby" {
		t.Errorf("auth/me: want tier=hobby, got %q", me["tier"])
	}
	if me["email"] != email {
		t.Errorf("auth/me: want email=%q, got %q", email, me["email"])
	}
}

// ── S4.3: GET /auth/me without Authorization → 401 ───────────────────────────

func TestE2E_AuthFlow_AuthMe_NoAuth_Returns401(t *testing.T) {
	resp := get(t, "/auth/me")
	body := readBody(t, resp)

	if resp.StatusCode != 401 {
		t.Errorf("GET /auth/me without auth: want 401, got %d\n%s", resp.StatusCode, body)
	}
}

// ── S4.4: GET /auth/me with malformed JWT → 401 ──────────────────────────────

func TestE2E_AuthFlow_AuthMe_MalformedJWT_Returns401(t *testing.T) {
	for _, bad := range []string{
		"Bearer notajwt",
		"Bearer eyJhbGciOiJub25lIn0.e30.",
		"Bearer a.b.c",
		"notbearer",
		"Bearer",
	} {
		resp := get(t, "/auth/me", "Authorization", bad)
		body := readBody(t, resp)
		if resp.StatusCode != 401 {
			t.Errorf("GET /auth/me with %q: want 401, got %d\n%s", bad, resp.StatusCode, body)
		}
	}
}

// ── S4.5: POST /claim same JWT twice concurrently → 1 wins, 1 conflicts ──────

func TestE2E_AuthFlow_Claim_DuplicateJWT_OneWinsOneConflicts(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)

	type result struct {
		code int
		body string
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp := post(t, "/claim", map[string]any{
				"jwt":   jwtStr,
				"email": "race-" + uuid.NewString()[:6] + "@instant.dev",
			})
			results[i] = result{code: resp.StatusCode, body: readBody(t, resp)}
		}()
	}
	wg.Wait()

	codes := [2]int{results[0].code, results[1].code}
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case 201:
			ok++
		case 409:
			conflict++
		}
	}
	if ok != 1 {
		t.Errorf("concurrent claim: want exactly 1 success (201), got %d (codes: %v)", ok, codes)
	}
	if conflict != 1 {
		t.Errorf("concurrent claim: want exactly 1 conflict (409), got %d (codes: %v)", conflict, codes)
	}
}

// ── S4.5b: Sequential double-claim → second is 409 ───────────────────────────

func TestE2E_AuthFlow_Claim_SecondClaim_Returns409(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)

	resp1 := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": uniqueEmail(),
	})
	if resp1.StatusCode != 201 {
		t.Fatalf("first POST /claim: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	resp1.Body.Close()

	time.Sleep(50 * time.Millisecond)

	resp2 := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": uniqueEmail(),
	})
	body2 := readBody(t, resp2)
	if resp2.StatusCode != 409 {
		t.Errorf("second POST /claim: want 409 (already_claimed), got %d\n%s", resp2.StatusCode, body2)
	}
}

// ── S4.6: POST /claim without email → 400 or 422 ─────────────────────────────

func TestE2E_AuthFlow_Claim_MissingEmail_Returns4xx(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)

	// No email field.
	resp := post(t, "/claim", map[string]any{"jwt": jwtStr})
	body := readBody(t, resp)

	if resp.StatusCode != 400 && resp.StatusCode != 422 {
		t.Errorf("POST /claim without email: want 400 or 422, got %d\n%s", resp.StatusCode, body)
	}
}

// ── S4.7: POST /claim with foreign JWT → 400 or 422 ──────────────────────────

func TestE2E_AuthFlow_Claim_ForeignJWT_Returns4xx(t *testing.T) {
	// A JWT signed with a different key.
	fakeJWT := "eyJhbGciOiJIUzI1NiJ9.eyJmcCI6ImZha2UiLCJ0b2siOltdLCJleHAiOjk5OTk5OTk5OTl9.fakesignature"

	resp := post(t, "/claim", map[string]any{
		"jwt":   fakeJWT,
		"email": uniqueEmail(),
	})
	body := readBody(t, resp)

	if resp.StatusCode != 400 && resp.StatusCode != 401 && resp.StatusCode != 422 {
		t.Errorf("POST /claim with foreign JWT: want 4xx, got %d\n%s", resp.StatusCode, body)
	}
}

// ── S4.8: After claim, GET /api/v1/resources includes the claimed cache token ─

func TestE2E_AuthFlow_Claim_ResourceListIncludesClaimedToken(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": email,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	if listResp.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &list)

	found := false
	for _, item := range list.Items {
		if tok, _ := item["token"].(string); tok == anonCache.Token {
			found = true
		}
	}
	if !found {
		t.Errorf("resource list must contain claimed cache token %q after claim; got %d items",
			anonCache.Token, len(list.Items))
	}
}

// ── S4.9: Claimed resource has no expires_at (persists forever) ──────────────

func TestE2E_AuthFlow_Claim_ClaimedResource_HasNoExpiresAt(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwtStr := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt":   jwtStr,
		"email": email,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d", claimResp.StatusCode)
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)

	listResp := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	var list struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &list)

	for _, item := range list.Items {
		if tok, _ := item["token"].(string); tok == anonCache.Token {
			if expiresAt, exists := item["expires_at"]; exists && expiresAt != nil {
				t.Errorf("claimed resource must not have expires_at, got %v", expiresAt)
			}
		}
	}
}
