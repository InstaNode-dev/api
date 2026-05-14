//go:build e2e

// Persona — Cross-Team IDOR (FIX-B / B44)
//
// End-to-end verification that the 18 cross-team ownership sites return
// 404 (not 403) when Team B probes a resource or deployment owned by
// Team A. 403 leaks the existence of cross-tenant rows; 404 keeps the
// id-space fully opaque.
//
// Flow per test:
//   1. Provision an anonymous resource from IP A → JWT_A.
//   2. Claim JWT_A with email_A → team_A + session_A.
//   3. Provision another anonymous resource from a different IP B → JWT_B.
//   4. Claim JWT_B with email_B → team_B + session_B.
//   5. With session_A's bearer token, hit team_B's resource/deployment id.
//   6. Assert 404 with error="not_found".
//
// Skips when E2E_JWT_SECRET is absent — same posture as every other E2E
// test that mints a session JWT.

package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// crossTeamPair sets up two claimed teams and returns session JWTs +
// the resource tokens each team owns. Used by every cross-team probe
// below so each test stays two-line readable.
type crossTeamPair struct {
	sessionA      string
	sessionB      string
	resourceAToken string
	resourceBToken string
	teamAID       string
	teamBID       string
}

func setupCrossTeamPair(t *testing.T) crossTeamPair {
	t.Helper()

	// Team A.
	ipA := uniqueIP(t)
	resA := provisionAnonymous(t, ipA)
	jwtA := extractJWTFromNote(t, resA.Note)
	emailA := uniqueEmail()
	claimRespA := post(t, "/claim", map[string]any{
		"jwt": jwtA, "email": emailA, "team_name": "e2e-ctA-" + uuid.NewString()[:6],
	})
	if claimRespA.StatusCode != 201 {
		t.Fatalf("claim team A: want 201, got %d\n%s",
			claimRespA.StatusCode, readBody(t, claimRespA))
	}
	var claimA claimResponse
	decodeJSON(t, claimRespA, &claimA)
	sessionA := makeSessionJWT(t, claimA.TeamID, emailA)

	// Team B.
	ipB := uniqueIP(t)
	resB := provisionAnonymous(t, ipB)
	jwtB := extractJWTFromNote(t, resB.Note)
	emailB := uniqueEmail()
	claimRespB := post(t, "/claim", map[string]any{
		"jwt": jwtB, "email": emailB, "team_name": "e2e-ctB-" + uuid.NewString()[:6],
	})
	if claimRespB.StatusCode != 201 {
		t.Fatalf("claim team B: want 201, got %d\n%s",
			claimRespB.StatusCode, readBody(t, claimRespB))
	}
	var claimB claimResponse
	decodeJSON(t, claimRespB, &claimB)
	sessionB := makeSessionJWT(t, claimB.TeamID, emailB)

	return crossTeamPair{
		sessionA:       sessionA,
		sessionB:       sessionB,
		resourceAToken: resA.Token,
		resourceBToken: resB.Token,
		teamAID:        claimA.TeamID,
		teamBID:        claimB.TeamID,
	}
}

// expectE2E404 issues `req` and asserts a 404 with error="not_found".
// Also pins the body shape: must NOT echo "You do not own" or the
// "forbidden" error code (those would be old 403 leak signals).
func expectE2E404(t *testing.T, resp *http.Response, label string) {
	t.Helper()
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("%s: want 404, got %d; body=%s", label, resp.StatusCode, body)
		return
	}
	if contains(body, "You do not own") {
		t.Errorf("%s: response body must not leak 'You do not own'; body=%s", label, body)
	}
	if contains(body, `"forbidden"`) {
		t.Errorf("%s: response body must not echo 'forbidden' error code; body=%s", label, body)
	}
	if !contains(body, `"not_found"`) {
		t.Errorf("%s: response body must carry error=\"not_found\"; body=%s", label, body)
	}
}

// TestE2E_CrossTeam_AllResourceEndpoints_Return404 — Team A's session JWT
// must NOT be able to reach Team B's resource on ANY of the 10 resource
// endpoints. Each gets its own subtest so a failure pinpoints the leaky
// site immediately.
func TestE2E_CrossTeam_AllResourceEndpoints_Return404(t *testing.T) {
	pair := setupCrossTeamPair(t)
	bearer := "Bearer " + pair.sessionA
	tok := pair.resourceBToken // Team B's resource probed by Team A.

	cases := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"GET /api/v1/resources/:id", http.MethodGet,
			"/api/v1/resources/" + tok, nil},
		{"DELETE /api/v1/resources/:id", http.MethodDelete,
			"/api/v1/resources/" + tok, nil},
		{"POST /api/v1/resources/:id/rotate-credentials", http.MethodPost,
			"/api/v1/resources/" + tok + "/rotate-credentials", nil},
		{"GET /api/v1/resources/:id/credentials", http.MethodGet,
			"/api/v1/resources/" + tok + "/credentials", nil},
		{"POST /api/v1/resources/:id/pause", http.MethodPost,
			"/api/v1/resources/" + tok + "/pause", nil},
		{"POST /api/v1/resources/:id/resume", http.MethodPost,
			"/api/v1/resources/" + tok + "/resume", nil},
		{"GET /api/v1/resources/:id/metrics", http.MethodGet,
			"/api/v1/resources/" + tok + "/metrics", nil},
		{"GET /api/v1/resources/:id/family", http.MethodGet,
			"/api/v1/resources/" + tok + "/family", nil},
		{"POST /api/v1/resources/:id/backup", http.MethodPost,
			"/api/v1/resources/" + tok + "/backup", nil},
		{"GET /api/v1/resources/:id/backups", http.MethodGet,
			"/api/v1/resources/" + tok + "/backups", nil},
		{"POST /api/v1/resources/:id/provision-twin", http.MethodPost,
			"/api/v1/resources/" + tok + "/provision-twin",
			map[string]any{"env": "staging"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			switch tc.method {
			case http.MethodGet:
				resp = get(t, tc.path, "Authorization", bearer)
			case http.MethodDelete:
				resp = doE2ERequest(t, http.MethodDelete, tc.path, nil, bearer)
			case http.MethodPost:
				resp = post(t, tc.path, tc.body, "Authorization", bearer)
			}
			expectE2E404(t, resp, tc.name)
		})
	}
}

// doE2ERequest is a tiny shim for verbs the helpers package doesn't
// already wrap (DELETE, PATCH). Kept local so it doesn't compete with
// the existing helpers' signatures.
func doE2ERequest(t *testing.T, method, path string, body any, bearer string) *http.Response {
	t.Helper()
	// Use the existing post() helper as a template via a request:
	// we build a request directly to keep this short.
	url := baseURL() + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("doE2ERequest %s %s: %v", method, path, err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("doE2ERequest %s %s: %v", method, path, err)
	}
	return resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Smoke check: Team A's OWN resource still returns 200 — proves the 404 is
// specifically about cross-team mismatch, not an across-the-board regression.
// ─────────────────────────────────────────────────────────────────────────────

func TestE2E_CrossTeam_OwnResource_Returns200(t *testing.T) {
	pair := setupCrossTeamPair(t)

	resp := get(t, "/api/v1/resources/"+pair.resourceAToken,
		"Authorization", "Bearer "+pair.sessionA)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Errorf("Team A reading its OWN resource: want 200, got %d; body=%s",
			resp.StatusCode, body)
	}
}
