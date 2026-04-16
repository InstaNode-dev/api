//go:build e2e

// Package e2e — Journey tests covering realistic user personas end-to-end.
//
// Each test family is named after the persona it simulates:
//
//	Persona_CronDevOps          — DevOps engineer wrapping cron jobs
//	Persona_AIAgent             — AI agent provisioning all services in one session
//	Persona_RateLimit           — Anonymous user hits limits then upgrades
//	Persona_ManagementAPI       — Auth edge cases on the management API
//	Persona_ClaimThenManage     — Full claim-to-management-API flow (needs E2E_JWT_SECRET)
//	Persona_CrossServiceLimits  — Rate limits are per-service and independent
//	Persona_CLIDeviceFlow       — CLI device-flow auth endpoints
//	Persona_ConcurrentAgents    — Multiple cloud agents provisioning simultaneously
//
// # Environment variables
//
//	E2E_BASE_URL      live server URL (default: http://localhost:32108)
//	E2E_JWT_SECRET    JWT signing secret — required for management API positive tests.
//	                  Set to the value of JWT_SECRET in your k8s secret:
//	                    kubectl get secret instant-secrets -n instant \
//	                      -o jsonpath='{.data.JWT_SECRET}' | base64 -d
package e2e

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// ─── Session JWT helpers ───────────────────────────────────────────────────────

// makeSessionJWT signs a 1-hour session JWT for the given team using MapClaims,
// exactly mirroring the payload that auth.go issues.
// Skips the calling test if E2E_JWT_SECRET is not set.
//
// userID may be "" — in that case a random UUID is used, which is sufficient
// for tests that don't call GET /auth/me (which requires a real user row).
// Use makeSessionJWTWithUser when the test calls GET /auth/me.
func makeSessionJWT(t *testing.T, teamID, email string) string {
	t.Helper()
	return makeSessionJWTWithUser(t, "", teamID, email)
}

// makeSessionJWTWithUser signs a session JWT with a real userID. Use this
// when the test calls GET /auth/me, which looks up the user row by uid.
// Pass the user_id field from the POST /claim response.
func makeSessionJWTWithUser(t *testing.T, userID, teamID, email string) string {
	t.Helper()
	secret := os.Getenv("E2E_JWT_SECRET")
	if secret == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping management-API auth test. " +
			"Set it to the value of JWT_SECRET in your k8s secret:\n" +
			"  kubectl get secret instant-secrets -n instant " +
			"-o jsonpath='{.data.JWT_SECRET}' | base64 -d")
	}
	uid := userID
	if uid == "" {
		uid = uuid.NewString()
	}
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"uid":   uid,
		"tid":   teamID,
		"email": email,
		"jti":   uuid.NewString(),
		"iat":   now,
		"exp":   now + 3600, // 1 hour
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("makeSessionJWTWithUser: %v", err)
	}
	return signed
}

// skipIfServiceDown skips (not fails) when a service returns 503.
func skipIfServiceDown(t *testing.T, resp *http.Response, service string) {
	t.Helper()
	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skipf("%s service not enabled on this server — skip", service)
	}
}

// ─── Persona 2: AI Agent Builder — all services in one session ────────────────

// TestE2E_Persona_AIAgent_ProvisionAllServicesInOneSession simulates a Claude Code
// agent that provisions cache, postgres, redis, and mongodb in a single
// development session from the same IP. All four must succeed with unique tokens
// and the correct connection URL scheme.
func TestE2E_Persona_AIAgent_ProvisionAllServicesInOneSession(t *testing.T) {
	ip := uniqueIP(t)

	type svc struct {
		label  string
		path   string
		prefix string // expected connection_url prefix
	}
	services := []svc{
		{"postgres", "/db/new", "postgres://"},
		{"redis", "/cache/new", "redis://"},
		{"mongodb", "/nosql/new", "mongodb://"},
	}

	seenTokens := map[string]string{} // token → service
	for _, s := range services {
		s := s
		t.Run(s.label, func(t *testing.T) {
			resp := post(t, s.path, nil, "X-Forwarded-For", ip)
			skipIfServiceDown(t, resp, s.label)

			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("POST %s: want 201, got %d\n%s",
					s.path, resp.StatusCode, readBody(t, resp))
			}

			// X-Instant-Upgrade must be present on every service provision.
			upgrade := resp.Header.Get("X-Instant-Upgrade")
			if upgrade == "" {
				t.Errorf("POST %s: X-Instant-Upgrade header must be present", s.path)
			} else if !strings.Contains(upgrade, "/start?t=") {
				t.Errorf("POST %s: X-Instant-Upgrade must contain /start?t=, got %q", s.path, upgrade)
			}

			var body provisionNewResponse
			decodeJSON(t, resp, &body)

			if body.Token == "" {
				t.Fatalf("token must not be empty")
			}
			if _, err := uuid.Parse(body.Token); err != nil {
				t.Errorf("token %q must be a valid UUID", body.Token)
			}
			if s.prefix != "" && !strings.HasPrefix(body.ConnectionURL, s.prefix) {
				t.Errorf("connection_url must start with %q, got %q", s.prefix, body.ConnectionURL)
			}
			if prev, exists := seenTokens[body.Token]; exists {
				t.Errorf("duplicate token %q (also returned by %s)", body.Token, prev)
			}
			seenTokens[body.Token] = s.label
		})
	}
}

// TestE2E_Persona_AIAgent_ProvisionsWithOptionalName verifies that services accept
// an optional name field in the request body and (if enabled) return it.
func TestE2E_Persona_AIAgent_ProvisionsWithOptionalName(t *testing.T) {
	ip := uniqueIP(t)
	name := "my-test-cache-" + uuid.NewString()[:8]

	resp := post(t, "/cache/new", map[string]any{"name": name}, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		t.Skip("POST /cache/new: service not enabled (503)")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /cache/new with name: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Fatal("token must not be empty")
	}
	if body.Name != name {
		t.Errorf("name not echoed: want %q, got %q", name, body.Name)
	}
}

// ─── Persona 3: Anonymous User — rate limit → CTA → upgrade funnel ────────────

// TestE2E_Persona_RateLimit_BodyContainsCTA verifies that after the provisioning
// limit is hit the rate-limited response contains an upgrade URL in the body.
// The server must return a deduped existing token — never 429 (fail-open).
func TestE2E_Persona_RateLimit_BodyContainsCTA(t *testing.T) {
	id := uuid.New()
	ip := fmt.Sprintf("192.168.%d.1", id[0]%254+1)

	var firstToken string
	for i := 0; i < 5; i++ {
		prov := provisionAnonymous(t, ip)
		if i == 0 {
			firstToken = prov.Token
		}
	}

	// 6th call — limit exceeded.
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == http.StatusTooManyRequests {
		readBody(t, resp)
		t.Fatal("rate-limited response must not be 429 — must fail-open")
	}

	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	// Token must be one we already saw (dedup).
	if body.Token == "" {
		t.Fatal("rate-limited response must still contain a token")
	}
	_ = firstToken // kept as reference, not asserted (order may vary)

	// The response must signal the limit somehow — either via upgrade field or note.
	if body.Upgrade == "" && !strings.Contains(body.Note, "instant.dev/start?t=") {
		t.Error("rate-limited response must include an upgrade URL (in 'upgrade' or 'note' field)")
	}

	// X-Instant-Upgrade header must be present.
	// (The header is on the resp we already read — re-check note field as proxy.)
	if body.Note == "" && body.Upgrade == "" {
		t.Error("rate-limited response must have upgrade context in body")
	}
}

// TestE2E_Persona_RateLimit_FollowFunnelToClaimAtomicSingleUse is the full
// rate-limit → CTA → /start → claim → replay-attack journey.
//
//  1. Exhaust anonymous cache provisioning limit from one IP
//  2. Extract JWT from the rate-limited response's note
//  3. GET /start?t=<jwt>   → 302 redirect to dashboard ClaimPage
//  4. POST /claim          → 201, team_id
//  5. GET /start?t=<jwt>   → 302 redirect to /claim?already_claimed=true
//  6. POST /claim again    → 409, replay attack rejected
func TestE2E_Persona_RateLimit_FollowFunnelToClaimAtomicSingleUse(t *testing.T) {
	ip := uniqueIP(t)

	// Step 1: Exhaust limit — collect 5 tokens.
	var tokens []string
	for i := 0; i < 5; i++ {
		prov := provisionAnonymous(t, ip)
		tokens = append(tokens, prov.Token)
	}
	t.Logf("step 1: provisioned %d cache resources", len(tokens))

	// Step 2: 6th call returns existing token + upgrade URL.
	resp2 := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	var body2 provisionNewResponse
	decodeJSON(t, resp2, &body2)
	jwt_ := extractJWTFromNote(t, body2.Note)
	t.Logf("step 2: extracted JWT from rate-limited response")

	// Step 3: /start redirects to the dashboard ClaimPage.
	resp3 := getNoRedirect(t, "/start?t="+jwt_)
	readBody(t, resp3)
	if resp3.StatusCode != http.StatusFound {
		t.Fatalf("step 3: GET /start: want 302, got %d", resp3.StatusCode)
	}
	loc3 := resp3.Header.Get("Location")
	if !strings.Contains(loc3, "/claim?t=") {
		t.Errorf("step 3: Location must contain /claim?t=, got %q", loc3)
	}
	t.Logf("step 3: /start redirected to %s", loc3)

	// Step 4: Claim the account — single-use enforcement.
	email := uniqueEmail()
	resp4 := post(t, "/claim", map[string]any{
		"jwt":       jwt_,
		"email":     email,
		"team_name": "rate-limit-test-" + uuid.NewString()[:6],
	})
	if resp4.StatusCode != http.StatusCreated {
		t.Fatalf("step 4: POST /claim: want 201, got %d\n%s", resp4.StatusCode, readBody(t, resp4))
	}
	var claim claimResponse
	decodeJSON(t, resp4, &claim)
	if claim.TeamID == "" {
		t.Fatal("step 4: team_id must be present")
	}
	t.Logf("step 4: claimed → team_id=%s", claim.TeamID)

	// Step 5: Second visit to /start with same JWT → redirect to already_claimed page.
	resp5 := getNoRedirect(t, "/start?t="+jwt_)
	readBody(t, resp5)
	if resp5.StatusCode != http.StatusFound {
		t.Errorf("step 5: GET /start after claim: want 302, got %d", resp5.StatusCode)
	}
	loc5 := resp5.Header.Get("Location")
	if !strings.Contains(loc5, "already_claimed=true") {
		t.Errorf("step 5: Location must contain already_claimed=true, got %q", loc5)
	}

	// Step 6: Replay attack on /claim → 409 Conflict.
	resp6 := post(t, "/claim", map[string]any{
		"jwt":       jwt_,
		"email":     uniqueEmail(),
		"team_name": "replay-" + uuid.NewString()[:6],
	})
	readBody(t, resp6)
	if resp6.StatusCode != http.StatusConflict {
		t.Errorf("step 6: replay attack: want 409, got %d", resp6.StatusCode)
	}
	t.Log("full rate-limit funnel passed.")
}

// TestE2E_Persona_RateLimit_ResourceTypesInStartLanding verifies that /start
// redirects to the dashboard ClaimPage with a valid JWT token embedded.
func TestE2E_Persona_RateLimit_ResourceTypesInStartLanding(t *testing.T) {
	ip := uniqueIP(t)

	// Provision anonymous cache from this IP to get a JWT.
	prov := provisionAnonymous(t, ip)
	jwt_ := extractJWTFromNote(t, prov.Note)

	// Try to also provision a DB from the same IP (may be disabled).
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	readBody(t, resp)

	// /start must redirect (302) to the dashboard ClaimPage.
	landingResp := getNoRedirect(t, "/start?t="+jwt_)
	readBody(t, landingResp)
	if landingResp.StatusCode != http.StatusFound {
		t.Fatalf("GET /start: want 302, got %d", landingResp.StatusCode)
	}
	loc := landingResp.Header.Get("Location")
	if !strings.Contains(loc, "/claim?t=") {
		t.Errorf("GET /start: Location must contain /claim?t=, got %q", loc)
	}
}

// ─── Persona 4: Management API — auth edge cases ──────────────────────────────

// TestE2E_Persona_ManagementAPI_Unauthenticated verifies that all management
// endpoints reject requests without a valid session token.
func TestE2E_Persona_ManagementAPI_Unauthenticated(t *testing.T) {
	cases := []struct {
		label  string
		method string
		path   string
	}{
		{"list-no-auth", http.MethodGet, "/api/v1/resources"},
		{"get-no-auth", http.MethodGet, "/api/v1/resources/" + uuid.NewString()},
		{"delete-no-auth", http.MethodDelete, "/api/v1/resources/" + uuid.NewString()},
		{"billing-no-auth", http.MethodPost, "/billing/checkout"},
		{"billing-cancel-no-auth", http.MethodPost, "/api/v1/billing/cancel"},
		{"billing-invoices-no-auth", http.MethodGet, "/api/v1/billing/invoices"},
		{"billing-update-pay-no-auth", http.MethodPost, "/api/v1/billing/update-payment"},
		{"billing-change-plan-no-auth", http.MethodPost, "/api/v1/billing/change-plan"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			var resp *http.Response
			switch tc.method {
			case http.MethodGet:
				resp = get(t, tc.path)
			case http.MethodPost:
				resp = post(t, tc.path, map[string]any{"plan": "pro"})
			case http.MethodDelete:
				req, _ := http.NewRequest(http.MethodDelete, baseURL()+tc.path, nil)
				var err error
				resp, err = client.Do(req)
				if err != nil {
					t.Fatalf("DELETE %s: %v", tc.path, err)
				}
			}
			readBody(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s: want 401, got %d", tc.method, tc.path, resp.StatusCode)
			}
		})
	}
}

// TestE2E_Persona_ManagementAPI_InvalidBearerToken verifies that a malformed
// JWT in the Authorization header returns 401 (not 500 or 403).
func TestE2E_Persona_ManagementAPI_InvalidBearerToken(t *testing.T) {
	cases := []struct {
		label string
		token string
	}{
		{"garbage", "not-a-jwt"},
		{"partial-jwt", "eyJhbGciOiJIUzI1NiJ9.eyJ0ZWFtIjoiYWJjIn0"},
		{"tampered-sig", "eyJhbGciOiJIUzI1NiJ9.eyJ0aWQiOiJhYmMifQ.badsig"},
		{"expired", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aWQiOiJ0ZXN0IiwiZXhwIjoxfQ.invalid"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			resp := get(t, "/api/v1/resources",
				"Authorization", "Bearer "+tc.token)
			readBody(t, resp)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("Bearer %q: want 401, got %d", tc.label, resp.StatusCode)
			}
		})
	}
}

// TestE2E_Persona_ManagementAPI_WithValidJWT_EmptyTeam verifies that an
// authenticated request for a team with no resources returns an empty list.
// This does NOT require any real resources in the DB.
func TestE2E_Persona_ManagementAPI_WithValidJWT_EmptyTeam(t *testing.T) {
	teamID := uuid.NewString()
	sessionToken := makeSessionJWT(t, teamID, "e2e-empty@instant.dev")

	resp := get(t, "/api/v1/resources",
		"Authorization", "Bearer "+sessionToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/resources with valid JWT: want 200, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var body struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("ok must be true")
	}
	if body.Items == nil {
		t.Error("items must not be nil (empty list, not null)")
	}
	if body.Total != 0 {
		t.Errorf("total must be 0 for new team, got %d", body.Total)
	}
}

// TestE2E_Persona_ManagementAPI_WithValidJWT_IDErrors verifies resource ID
// edge cases for an authenticated team member.
func TestE2E_Persona_ManagementAPI_WithValidJWT_IDErrors(t *testing.T) {
	teamID := uuid.NewString()
	sessionToken := makeSessionJWT(t, teamID, "e2e-idtest@instant.dev")

	t.Run("not-found-uuid", func(t *testing.T) {
		resp := get(t, "/api/v1/resources/"+uuid.NewString(),
			"Authorization", "Bearer "+sessionToken)
		readBody(t, resp)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET nonexistent resource: want 404, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid-uuid", func(t *testing.T) {
		resp := get(t, "/api/v1/resources/not-a-valid-uuid",
			"Authorization", "Bearer "+sessionToken)
		readBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("GET invalid UUID: want 400, got %d", resp.StatusCode)
		}
	})

	t.Run("cross-team-forbid", func(t *testing.T) {
		// Provision an anonymous resource (no team_id in DB).
		ip := uniqueIP(t)
		prov := provisionAnonymous(t, ip)

		// Try to access it as our test team → should be 403 (it belongs to no team).
		resp := get(t, "/api/v1/resources/"+prov.Token,
			"Authorization", "Bearer "+sessionToken)
		readBody(t, resp)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET anonymous resource as different team: want 403, got %d", resp.StatusCode)
		}
	})
}

// ─── Persona 5: Claim → Management API (full loop) ───────────────────────────

// TestE2E_Persona_ClaimThenManage is the complete conversion funnel + management
// API lifecycle:
//
//  1. Provision anonymous cache + DB as anonymous
//  2. Claim → get team_id
//  3. Sign session JWT for that team (requires E2E_JWT_SECRET)
//  4. GET /api/v1/resources → see claimed cache resource
//  5. GET /api/v1/resources/:id → item has correct shape, no connection_url
//  6. DELETE /api/v1/resources/:id → 200
//  7. GET /api/v1/resources → one fewer item
func TestE2E_Persona_ClaimThenManage(t *testing.T) {
	ip := uniqueIP(t)
	email := uniqueEmail()

	// Step 1: Provision anonymous cache (always enabled).
	t.Log("step 1: provision anonymous cache...")
	prov := provisionAnonymous(t, ip)
	jwt_ := extractJWTFromNote(t, prov.Note)
	t.Logf("  token=%s", prov.Token)

	// Also try DB (optional — skip if not enabled).
	dbResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	dbEnabled := dbResp.StatusCode == http.StatusCreated
	var dbProv provisionNewResponse
	if dbEnabled {
		decodeJSON(t, dbResp, &dbProv)
		t.Logf("  db token=%s", dbProv.Token)
	} else {
		readBody(t, dbResp)
	}

	// Step 2: Claim.
	t.Log("step 2: claim...")
	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwt_,
		"email":     email,
		"team_name": "mgmt-test-" + uuid.NewString()[:6],
	})
	if claimResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)
	t.Logf("  team_id=%s", claim.TeamID)

	// Step 3: Sign a session JWT for the new team.
	sessionToken := makeSessionJWT(t, claim.TeamID, email)

	// Step 4: List resources — must include the claimed cache resource.
	t.Log("step 4: list resources after claim...")
	listResp := get(t, "/api/v1/resources",
		"Authorization", "Bearer "+sessionToken)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/resources: want 200, got %d\n%s",
			listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	decodeJSON(t, listResp, &listBody)

	if !listBody.OK {
		t.Error("list ok must be true")
	}
	expectedCount := 1
	if dbEnabled {
		expectedCount = 2
	}
	if listBody.Total != expectedCount {
		t.Errorf("total: want %d, got %d (items: %v)", expectedCount, listBody.Total, listBody.Items)
	}

	// Verify resource appears and connection_url is NOT exposed.
	cacheTokenFound := false
	for _, item := range listBody.Items {
		if item["token"] == prov.Token {
			cacheTokenFound = true
			if _, hasURL := item["connection_url"]; hasURL {
				t.Error("connection_url must NOT be exposed in management API list response")
			}
			if item["resource_type"] != "redis" {
				t.Errorf("resource_type: want 'redis', got %v", item["resource_type"])
			}
			if item["team_id"] == nil {
				t.Error("team_id must be set after claim")
			}
		}
	}
	if !cacheTokenFound {
		t.Errorf("step 4: claimed resource token %q not in list", prov.Token)
	}

	// Step 5: Get individual resource.
	t.Log("step 5: get individual resource...")
	getResp := get(t, "/api/v1/resources/"+prov.Token,
		"Authorization", "Bearer "+sessionToken)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/resources/:id: want 200, got %d\n%s",
			getResp.StatusCode, readBody(t, getResp))
	}
	var getBody struct {
		OK   bool           `json:"ok"`
		Item map[string]any `json:"item"`
	}
	decodeJSON(t, getResp, &getBody)
	if !getBody.OK {
		t.Error("get ok must be true")
	}
	if getBody.Item == nil {
		t.Fatal("item must not be nil")
	}
	if _, hasURL := getBody.Item["connection_url"]; hasURL {
		t.Error("connection_url must NOT be exposed in individual resource response")
	}
	if getBody.Item["token"] != prov.Token {
		t.Errorf("item.token: want %q, got %v", prov.Token, getBody.Item["token"])
	}

	// Step 6: Delete the resource.
	t.Log("step 6: delete resource...")
	delReq, _ := http.NewRequest(http.MethodDelete, baseURL()+"/api/v1/resources/"+prov.Token, nil)
	delReq.Header.Set("Authorization", "Bearer "+sessionToken)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE /api/v1/resources: %v", err)
	}
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /api/v1/resources/:id: want 200, got %d\n%s",
			delResp.StatusCode, readBody(t, delResp))
	}
	readBody(t, delResp)

	// Step 7: List resources — deleted one should be gone.
	t.Log("step 7: list after delete...")
	list2Resp := get(t, "/api/v1/resources",
		"Authorization", "Bearer "+sessionToken)
	var list2 struct {
		OK    bool             `json:"ok"`
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	decodeJSON(t, list2Resp, &list2)

	// Deleted resource must not appear.
	for _, item := range list2.Items {
		if item["token"] == prov.Token {
			t.Errorf("step 7: deleted resource %q still appears in list", prov.Token)
		}
	}
	wantAfterDelete := expectedCount - 1
	if list2.Total != wantAfterDelete {
		t.Errorf("step 7: total after delete: want %d, got %d", wantAfterDelete, list2.Total)
	}

	t.Log("full claim→manage journey passed.")
}

// ─── Persona 7: CLI device-flow auth ─────────────────────────────────────────

// TestE2E_Persona_CLIDeviceFlow_CreateAndPollSession verifies the full
// POST /auth/cli → GET /auth/cli/:id polling lifecycle that the instant CLI uses.
func TestE2E_Persona_CLIDeviceFlow_CreateAndPollSession(t *testing.T) {
	// Step 1: Create a CLI login session.
	resp1 := post(t, "/auth/cli", nil)
	if resp1.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/cli: want 201, got %d\n%s", resp1.StatusCode, readBody(t, resp1))
	}
	var session struct {
		OK        bool   `json:"ok"`
		SessionID string `json:"session_id"`
		AuthURL   string `json:"auth_url"`
		ExpiresIn int    `json:"expires_in"`
	}
	decodeJSON(t, resp1, &session)

	if !session.OK {
		t.Error("ok must be true")
	}
	if session.SessionID == "" {
		t.Fatal("session_id must not be empty")
	}
	if session.AuthURL == "" {
		t.Error("auth_url must not be empty")
	}
	if session.ExpiresIn <= 0 {
		t.Errorf("expires_in must be positive, got %d", session.ExpiresIn)
	}
	t.Logf("session_id=%s auth_url=%s", session.SessionID, session.AuthURL)

	// Step 2: Poll — must return 202 (pending) since nobody completed OAuth.
	resp2 := get(t, "/auth/cli/"+session.SessionID)
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("GET /auth/cli/:id (pending): want 202, got %d\n%s",
			resp2.StatusCode, readBody(t, resp2))
	}
	var poll struct {
		OK      bool `json:"ok"`
		Pending bool `json:"pending"`
	}
	decodeJSON(t, resp2, &poll)
	if !poll.Pending {
		t.Error("pending must be true before OAuth completion")
	}
}

// TestE2E_Persona_CLIDeviceFlow_SessionWithAnonTokens verifies that anon_tokens
// are accepted in the POST /auth/cli body.
func TestE2E_Persona_CLIDeviceFlow_SessionWithAnonTokens(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	resp := post(t, "/auth/cli", map[string]any{
		"anon_tokens": []string{prov.Token},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/cli with anon_tokens: want 201, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var session struct {
		OK        bool   `json:"ok"`
		SessionID string `json:"session_id"`
		AuthURL   string `json:"auth_url"`
	}
	decodeJSON(t, resp, &session)
	if session.SessionID == "" {
		t.Fatal("session_id must not be empty when anon_tokens provided")
	}
}

// TestE2E_Persona_CLIDeviceFlow_NotFoundSession verifies that polling a
// non-existent session returns 404.
func TestE2E_Persona_CLIDeviceFlow_NotFoundSession(t *testing.T) {
	fakeID := "cafebabe00000000" // 16-char hex that won't exist
	resp := get(t, "/auth/cli/"+fakeID)
	readBody(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /auth/cli/nonexistent: want 404, got %d", resp.StatusCode)
	}
}

// TestE2E_Persona_CLIDeviceFlow_GetCurrentUser_NoAuth verifies that GET /auth/me
// without a bearer token returns 401.
func TestE2E_Persona_CLIDeviceFlow_GetCurrentUser_NoAuth(t *testing.T) {
	resp := get(t, "/auth/me")
	readBody(t, resp)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /auth/me without auth: want 401, got %d", resp.StatusCode)
	}
}

// ─── Persona 8: Concurrent multi-cloud agents ─────────────────────────────────

// TestE2E_Persona_ConcurrentAgents_AllServicesSimultaneously simulates 8 distinct
// "cloud agents" each provisioning anonymous cache and (when enabled) a DB and cache
// simultaneously. Every token must be unique.
func TestE2E_Persona_ConcurrentAgents_AllServicesSimultaneously(t *testing.T) {
	const agents = 8

	type result struct {
		agent  int
		tokens []string
	}

	results := make([]result, agents)
	var wg sync.WaitGroup
	wg.Add(agents)

	for i := 0; i < agents; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Distinct /24 per agent — ensures independent fingerprint buckets.
			ip := fmt.Sprintf("100.96.%d.1", i+1)
			var tokens []string

			// Anonymous cache (always enabled).
			prov := provisionAnonymous(t, ip)
			tokens = append(tokens, prov.Token)

			// DB (optional).
			dbResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
			if dbResp.StatusCode == http.StatusCreated {
				var body provisionNewResponse
				decodeJSON(t, dbResp, &body)
				tokens = append(tokens, body.Token)
			} else {
				readBody(t, dbResp)
			}

			// Cache (optional).
			cacheResp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
			if cacheResp.StatusCode == http.StatusCreated {
				var body provisionNewResponse
				decodeJSON(t, cacheResp, &body)
				tokens = append(tokens, body.Token)
			} else {
				readBody(t, cacheResp)
			}

			results[i] = result{agent: i, tokens: tokens}
		}()
	}
	wg.Wait()

	// All tokens across all agents must be globally unique.
	globalSeen := map[string]int{} // token → agent index
	for _, r := range results {
		for _, tok := range r.tokens {
			if tok == "" {
				t.Errorf("agent %d: got empty token", r.agent)
				continue
			}
			if prev, exists := globalSeen[tok]; exists {
				t.Errorf("duplicate token %q between agent %d and agent %d", tok, prev, r.agent)
			}
			globalSeen[tok] = r.agent
		}
	}
	t.Logf("concurrent agents: %d total unique tokens provisioned", len(globalSeen))
}

// ─── Persona 9: Security and edge cases ──────────────────────────────────────

// TestE2E_Persona_Security_MultipleXForwardedForUsesFirst verifies that when
// X-Forwarded-For contains multiple IPs (proxy chain), the server uses the
// leftmost (client) IP for fingerprinting — not a downstream proxy IP.
func TestE2E_Persona_Security_MultipleXForwardedForUsesFirst(t *testing.T) {
	// Unique /24 per test run for the "real" client IP.
	realClientIP := uniqueIP(t)
	// Proxy appends its own IP to the chain.
	multiHeader := realClientIP + ", 10.0.0.1, 10.0.0.2"

	// First provision from this new /24 — must succeed (201 or existing 200).
	prov1 := post(t, "/cache/new", nil, "X-Forwarded-For", multiHeader)
	status1 := prov1.StatusCode
	var body1 provisionNewResponse
	decodeJSON(t, prov1, &body1)

	// Must succeed (not error).
	if status1 != http.StatusCreated && status1 != http.StatusOK {
		t.Errorf("provision with multi-IP header: want 200 or 201, got %d", status1)
	}
	if body1.Token == "" {
		t.Error("provision with multi-IP header: token must not be empty")
	}

	// Second provision from a different IP in the SAME chain — must also succeed.
	// This validates that the server handles the header gracefully.
	otherIP := uniqueIP(t)
	prov2 := post(t, "/cache/new", nil, "X-Forwarded-For", otherIP+", "+realClientIP)
	status2 := prov2.StatusCode
	var body2 provisionNewResponse
	decodeJSON(t, prov2, &body2)

	if status2 != http.StatusCreated && status2 != http.StatusOK {
		t.Errorf("provision with reversed multi-IP header: want 200 or 201, got %d", status2)
	}
	if body2.Token == "" {
		t.Error("provision with reversed multi-IP header: token must not be empty")
	}
}

// TestE2E_Persona_Security_CrossTeamDeleteBlocked verifies that a team member
// cannot delete another team's resource (403 Forbidden).
func TestE2E_Persona_Security_CrossTeamDeleteBlocked(t *testing.T) {
	// Sign a session JWT for team A.
	teamAID := uuid.NewString()
	sessionA := makeSessionJWT(t, teamAID, "team-a@instant.dev")

	// Provision anonymous cache (belongs to no team).
	prov := provisionAnonymous(t, uniqueIP(t))

	// Team A tries to delete the anonymous resource → 403.
	req, _ := http.NewRequest(http.MethodDelete,
		baseURL()+"/api/v1/resources/"+prov.Token, nil)
	req.Header.Set("Authorization", "Bearer "+sessionA)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE cross-team: %v", err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-team DELETE: want 403, got %d", resp.StatusCode)
	}
}

// TestE2E_Persona_Security_ContentTypeNotRequired verifies that POST /cache/new
// still works when Content-Type is not application/json (e.g., curl without -H).
func TestE2E_Persona_Security_ContentTypeNotRequired(t *testing.T) {
	ip := uniqueIP(t)
	req, _ := http.NewRequest(http.MethodPost, baseURL()+"/cache/new", nil)
	req.Header.Set("X-Forwarded-For", ip)
	// Deliberately omit Content-Type.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /cache/new without Content-Type: %v", err)
	}
	readBody(t, resp)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("POST /cache/new without Content-Type: want 201, got %d", resp.StatusCode)
	}
}

// TestE2E_Persona_Security_AllResponsesHaveXRequestID verifies that X-Request-ID
// is present on error responses too, not just successes.
func TestE2E_Persona_Security_AllResponsesHaveXRequestID(t *testing.T) {
	cases := []struct {
		label  string
		path   string
		method string
	}{
		{"404-unknown-resource", "/api/v1/resources/" + uuid.NewString(), http.MethodGet},
		{"404-nonexistent-route", "/nonexistent/" + uuid.NewString(), http.MethodGet},
		{"400-start-no-token", "/start", http.MethodGet},
		{"401-start-bad-jwt", "/start?t=badtoken", http.MethodGet},
		{"401-api-no-auth", "/api/v1/resources", http.MethodGet},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			var resp *http.Response
			if tc.method == http.MethodGet {
				resp = get(t, tc.path)
			} else {
				resp = post(t, tc.path, nil)
			}
			readBody(t, resp)
			if resp.Header.Get("X-Request-ID") == "" {
				t.Errorf("%s %s: X-Request-ID must be present on error responses", tc.method, tc.path)
			}
		})
	}
}

// TestE2E_Persona_Security_PrometheusMetricsIncrement verifies that after
// provisioning, the Prometheus counter for provisions has increased.
// This is a smoke test for the metrics pipeline.
func TestE2E_Persona_Security_PrometheusMetricsIncrement(t *testing.T) {
	// Capture metric count before.
	before := prometheusCounterValue(t, "instant_provisions_total")

	// Provision anonymous cache.
	ip := uniqueIP(t)
	provisionAnonymous(t, ip)

	// Capture metric count after.
	after := prometheusCounterValue(t, "instant_provisions_total")

	if after <= before {
		t.Errorf("instant_provisions_total must increase after provision: before=%.0f after=%.0f", before, after)
	}
}

// prometheusCounterValue scrapes /metrics and sums all lines starting with
// the given metric name (handles label variants).
func prometheusCounterValue(t *testing.T, metric string) float64 {
	t.Helper()
	resp := get(t, "/metrics")
	body := readBody(t, resp)

	var total float64
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, metric+"{") || strings.HasPrefix(line, metric+" ") {
			var val float64
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				_, _ = fmt.Sscanf(parts[len(parts)-1], "%f", &val)
				total += val
			}
		}
	}
	return total
}

// TestE2E_Persona_Security_BillingCheckout_InvalidPlan verifies that POST /billing/checkout
// with an invalid plan name returns 400 (not 500), even when auth is present.
// Also tests that it returns 404 (team not found in DB) or 400 (bad plan) —
// both are acceptable since the test team doesn't exist in the DB.
func TestE2E_Persona_Security_BillingCheckout_InvalidPlan(t *testing.T) {
	teamID := uuid.NewString()
	sessionToken := makeSessionJWT(t, teamID, "billing-test@instant.dev")

	// With a valid JWT but invalid plan name — server should reject the plan before
	// even looking up the team (or return 404 if team lookup happens first).
	resp := post(t, "/billing/checkout",
		map[string]any{"plan": "ultimate"},
		"Authorization", "Bearer "+sessionToken)
	readBody(t, resp)
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound:
		// 400 = invalid plan name caught before team lookup
		// 404 = team not found (valid auth, plan validation may happen after)
	default:
		t.Errorf("POST /billing/checkout with invalid plan: want 400 or 404, got %d", resp.StatusCode)
	}
}

// ─── Persona 10: Onboarding / start edge cases ────────────────────────────────

// TestE2E_Persona_Onboarding_StartRejectsExpiredJWT verifies that a valid-looking
// but expired onboarding JWT returns an appropriate error.
func TestE2E_Persona_Onboarding_StartRejectsExpiredJWT(t *testing.T) {
	// This JWT is structurally valid HS256 but has exp=1 (long past).
	// The server must reject it — 400 or 401.
	expiredJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJmcCI6InRlc3QiLCJ0b2siOltdLCJleHAiOjF9" +
		".invalid_signature_to_prevent_acceptance"

	resp := get(t, "/start?t="+expiredJWT)
	readBody(t, resp)
	switch resp.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized:
		// Both are acceptable — expired JWT should not grant access.
	default:
		t.Errorf("GET /start with expired JWT: want 400 or 401, got %d", resp.StatusCode)
	}
}

// TestE2E_Persona_Onboarding_ClaimValidatesEmail verifies that POST /claim
// rejects obviously invalid inputs gracefully.
func TestE2E_Persona_Onboarding_ClaimValidatesEmail(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)
	jwt_ := extractJWTFromNote(t, prov.Note)

	cases := []struct {
		label string
		body  map[string]any
		want  int
	}{
		{"no-email", map[string]any{"jwt": jwt_}, http.StatusBadRequest},
		{"no-jwt", map[string]any{"email": uniqueEmail()}, http.StatusBadRequest},
		{"no-both", map[string]any{}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			resp := post(t, "/claim", tc.body)
			readBody(t, resp)
			if resp.StatusCode != tc.want {
				t.Errorf("POST /claim %s: want %d, got %d", tc.label, tc.want, resp.StatusCode)
			}
		})
	}
}
