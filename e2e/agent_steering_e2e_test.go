//go:build e2e

package e2e

// agent_steering_e2e_test.go — live e2e coverage for the 2026-06-10 agent-DX
// fixes against the LIVE api (api.instanode.dev by default):
//
//   D1/D8 — a 401 agent_action steers a headless agent at the CLI device-flow +
//           INSTANT_TOKEN, NOT the browser /login.
//   D6    — a live 401 body carries error_code.
//   D7    — an unknown provision field is echoed back under ignored_fields.
//   F1    — a recycle-gate 402 returns a claim_url carrying ?t=<jwt>.
//   D2    — `instant login` works end-to-end: mint cohort session → POST
//           /auth/cli → POST /auth/cli/{id}/complete → poll returns api_token.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestE2E_AgentSteering_Unauthorized401_SteersAtDeviceFlow (D1/D6/D8). An
// unauthenticated call to a RequireAuth-gated route returns 401 whose
// agent_action points at the CLI device-flow / INSTANT_TOKEN (not /login) and
// whose body carries error_code.
func TestE2E_AgentSteering_Unauthorized401_SteersAtDeviceFlow(t *testing.T) {
	resp := get(t, "/api/v1/resources") // RequireAuth, no Bearer → 401
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/resources without auth: want 401, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var body map[string]any
	decodeJSON(t, resp, &body)

	if body["error"] != "unauthorized" {
		t.Errorf("error must stay 'unauthorized' for back-compat; got %v", body["error"])
	}
	// D6: error_code present.
	ec, _ := body["error_code"].(string)
	if ec == "" {
		t.Errorf("D6: live 401 body must carry a non-empty error_code; got %v", body["error_code"])
	}
	// D1/D8: agent_action steers at the device-flow + INSTANT_TOKEN, not /login.
	action, _ := body["agent_action"].(string)
	if action == "" {
		t.Fatalf("agent_action must be present on a 401")
	}
	if !strings.Contains(action, "INSTANT_TOKEN") {
		t.Errorf("D8: agent_action must name INSTANT_TOKEN; got %q", action)
	}
	if strings.Contains(action, "INSTANODE_TOKEN") {
		t.Errorf("D8: agent_action must NOT name the old INSTANODE_TOKEN; got %q", action)
	}
	if !strings.Contains(action, "/auth/cli") {
		t.Errorf("D1: agent_action must steer at the CLI device-flow (/auth/cli); got %q", action)
	}
	if strings.Contains(action, "/login") {
		t.Errorf("D1: agent_action must NOT push a headless agent at /login; got %q", action)
	}
}

// TestE2E_AgentSteering_UnknownProvisionField_EchoedAsIgnored (D7). A provision
// body carrying an unrecognized key ("region") succeeds (201) and echoes the
// key under ignored_fields. Uses the anonymous /cache/new path (Redis — live in
// prod, unlike /db/new which is Phase-2-gated) with a unique fingerprint so it
// doesn't collide with the recycle gate.
func TestE2E_AgentSteering_UnknownProvisionField_EchoedAsIgnored(t *testing.T) {
	ip := uniqueIP(t)
	// Explicit name (so the test owns it) + an unknown "region" key.
	resp := post(t, "/cache/new",
		map[string]any{"name": "ignored-fields-probe", "region": "mars"},
		"X-Forwarded-For", ip)
	if resp.StatusCode == http.StatusServiceUnavailable {
		t.Skip("POST /cache/new: service not enabled (503) — skipping D7 live check")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /cache/new with unknown field: want 201, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
	var body map[string]any
	decodeJSON(t, resp, &body)

	raw, ok := body["ignored_fields"]
	if !ok {
		t.Fatalf("D7: 201 response must echo ignored_fields for an unknown key; body=%v", body)
	}
	arr, ok := raw.([]any)
	if !ok {
		t.Fatalf("ignored_fields must be an array; got %T (%v)", raw, raw)
	}
	found := false
	for _, v := range arr {
		if s, _ := v.(string); s == "region" {
			found = true
		}
	}
	if !found {
		t.Errorf("D7: ignored_fields must contain 'region'; got %v", arr)
	}
}

// TestE2E_AgentSteering_RecycleGate402_ClaimURLHasToken (F1). When the free-tier
// recycle gate fires (402 free_tier_recycle_requires_claim), the claim_url must
// embed a minted claim JWT (?t=). Driving the gate deterministically against a
// live cluster is timing-dependent (it needs a prior provision to have aged
// out), so this test only ASSERTS the contract IF it observes the gate — it
// never forces a sleep/aging loop (would violate rate-limit discipline). It is
// a no-op (skip) when the gate doesn't fire in this run.
func TestE2E_AgentSteering_RecycleGate402_ClaimURLHasToken(t *testing.T) {
	if e2eTestToken() == "" {
		t.Skip("E2E_TEST_TOKEN unset — cannot isolate a fingerprint to drive the recycle gate; skipping F1 live check")
	}
	// A single anonymous provision on a fresh fingerprint sets the
	// recycle_seen marker but won't itself gate (there's an active row). The
	// deterministic gate path is exercised by the unit test
	// (TestRecycleGate_FiresWith402_WhenMarkerExistsAndNoActiveRow); here we
	// only validate the live contract opportunistically.
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Skipf("recycle gate did not fire on this run (got %d) — F1 contract proven by the unit test; skipping live assert", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode 402 body: %v", err)
	}
	if body["error"] != "free_tier_recycle_requires_claim" {
		t.Fatalf("unexpected 402 error code: %v", body["error"])
	}
	claimURL, _ := body["claim_url"].(string)
	if !strings.Contains(claimURL, "?t=") {
		t.Errorf("F1: recycle-gate claim_url must embed a minted claim JWT (?t=); got %q", claimURL)
	}
}

// TestE2E_CLIDeviceFlow_Complete_FlipsSessionLive (D2). The full `instant login`
// round-trip against the live api: mint a cohort session, create a CLI session,
// complete it with the cohort Bearer, and poll for the api_token. Cohort is
// reaped on teardown.
func TestE2E_CLIDeviceFlow_Complete_FlipsSessionLive(t *testing.T) {
	c, reap := mintCohort(t, "free")
	defer reap()

	// 1. Create a pending CLI session.
	createResp := post(t, "/auth/cli", map[string]any{})
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/cli: want 201, got %d\n%s", createResp.StatusCode, readBody(t, createResp))
	}
	var created struct {
		SessionID string `json:"session_id"`
	}
	decodeJSON(t, createResp, &created)
	if created.SessionID == "" {
		t.Fatalf("POST /auth/cli returned no session_id")
	}

	// 2. Complete it with the cohort's session Bearer.
	completeResp := post(t, "/auth/cli/"+created.SessionID+"/complete", nil,
		"Authorization", "Bearer "+c.SessionJWT)
	if completeResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/cli/{id}/complete: want 200, got %d\n%s",
			completeResp.StatusCode, readBody(t, completeResp))
	}
	var done struct {
		OK bool `json:"ok"`
	}
	decodeJSON(t, completeResp, &done)
	if !done.OK {
		t.Fatalf("complete response must be {ok:true}")
	}

	// 3. Poll — must now return 200 + status:"complete" + a real api_token.
	pollResp := get(t, "/auth/cli/"+created.SessionID)
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/cli/{id} after complete: want 200, got %d\n%s",
			pollResp.StatusCode, readBody(t, pollResp))
	}
	var poll map[string]any
	decodeJSON(t, pollResp, &poll)
	if poll["status"] != "complete" {
		t.Errorf("D2: completed poll must carry status='complete'; got %v", poll["status"])
	}
	apiToken, _ := poll["api_token"].(string)
	if apiToken == "" || !strings.HasPrefix(apiToken, "ink_") {
		t.Errorf("D2: completed poll must return a real api_token (ink_...); got %q", apiToken)
	}
}
