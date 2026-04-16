//go:build e2e

// Webhook E2E tests — POST /webhook/new, POST /webhook/receive/:token,
// GET /api/v1/webhooks/:token/requests.
//
// Test groups:
//
//	TestE2E_Webhook_ServiceDisabled_Or_ValidShape   — 503 or 201 with correct shape
//	TestE2E_Webhook_ReceiveURL_AcceptsPost          — provision then POST to receive_url, verify stored
//	TestE2E_Webhook_Dedup                           — same fingerprint × 6, 6th returns existing
//
// Webhook service status:
//
//	The webhook service is feature-flagged via INSTANT_ENABLED_SERVICES.
//	When absent, the server returns 503. All tests detect 503 or 404 and skip
//	gracefully so the suite is safe to run against any cluster state.
//
// Required env vars (optional — tests skip when absent):
//
//	E2E_BASE_URL     live server (default: http://localhost:30080)
//	E2E_JWT_SECRET   required for authenticated list-requests test
package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ── Webhook helpers ───────────────────────────────────────────────────────────

// webhookServiceDisabled returns true (and skips the test) when the endpoint
// responds with 404 (route not deployed) or 503 (feature-flagged off).
// The caller must still drain the response body before calling this helper.
func webhookServiceDisabled(t *testing.T, statusCode int) bool {
	t.Helper()
	if statusCode == http.StatusNotFound || statusCode == http.StatusServiceUnavailable {
		t.Skipf("webhook service not enabled (HTTP %d) — skipping", statusCode)
		return true
	}
	return false
}

// webhookProvisionResponse is the response shape for POST /webhook/new.
type webhookProvisionResponse struct {
	OK         bool           `json:"ok"`
	ID         string         `json:"id"`
	Token      string         `json:"token"`
	ReceiveURL string         `json:"receive_url"`
	Tier       string         `json:"tier"`
	Limits     map[string]any `json:"limits"`
	Note       string         `json:"note"`
	Upgrade    string         `json:"upgrade,omitempty"`
	ExpiresAt  string         `json:"expires_at,omitempty"`
}

// provisionWebhook calls POST /webhook/new with the given X-Forwarded-For IP
// and returns the parsed response. Skips the test if the service is disabled.
func provisionWebhook(t *testing.T, ip string) webhookProvisionResponse {
	t.Helper()
	resp := post(t, "/webhook/new", nil, "X-Forwarded-For", ip)
	if webhookServiceDisabled(t, resp.StatusCode) {
		return webhookProvisionResponse{}
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /webhook/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body webhookProvisionResponse
	decodeJSON(t, resp, &body)
	return body
}

// ── TestE2E_Webhook_ServiceDisabled_Or_ValidShape ────────────────────────────
//
// Always-run: detects whether the service is disabled (skip) or live (validate shape).

func TestE2E_Webhook_ServiceDisabled_Or_ValidShape(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/webhook/new", nil, "X-Forwarded-For", ip)

	// Service disabled paths — skip gracefully.
	if resp.StatusCode == http.StatusNotFound {
		body := readBody(t, resp)
		t.Skipf("POST /webhook/new: 404 — route not deployed on this cluster (body: %s)", body)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody errorResponse
		decodeJSON(t, resp, &errBody)
		if errBody.Error != "service_disabled" {
			t.Errorf("503 from /webhook/new must carry error=service_disabled, got %q", errBody.Error)
		}
		t.Skipf("POST /webhook/new: 503 service_disabled — webhook not yet in INSTANT_ENABLED_SERVICES")
	}

	// Service is live — validate full response shape.
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /webhook/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body webhookProvisionResponse
	decodeJSON(t, resp, &body)

	if !body.OK {
		t.Error("ok field must be true")
	}
	if body.Token == "" {
		t.Error("token field must not be empty")
	}
	if _, err := uuid.Parse(body.Token); err != nil {
		t.Errorf("token %q must be a valid UUID: %v", body.Token, err)
	}
	if body.ID == "" {
		t.Error("id field must not be empty")
	}
	if _, err := uuid.Parse(body.ID); err != nil {
		t.Errorf("id %q must be a valid UUID: %v", body.ID, err)
	}
	if !strings.Contains(body.ReceiveURL, "/webhook/receive/") {
		t.Errorf("receive_url must contain /webhook/receive/; got %q", body.ReceiveURL)
	}
	if !strings.HasSuffix(body.ReceiveURL, body.Token) {
		t.Errorf("receive_url must end with the token %q; got %q", body.Token, body.ReceiveURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("unauthenticated provision must produce anonymous tier, got %q", body.Tier)
	}
	if body.Limits == nil {
		t.Error("limits field must not be nil")
	}
	if requestsStored, ok := body.Limits["requests_stored"].(float64); !ok || requestsStored != 100 {
		t.Errorf("limits.requests_stored must be 100, got %v", body.Limits["requests_stored"])
	}
	if expiresIn, ok := body.Limits["expires_in"].(string); !ok || expiresIn != "24h" {
		t.Errorf("limits.expires_in must be '24h', got %v", body.Limits["expires_in"])
	}
	if body.Note == "" {
		t.Error("note field must not be empty")
	}
}

// ── TestE2E_Webhook_ReceiveURL_AcceptsPost ───────────────────────────────────
//
// Only runs when webhook IS enabled.
// Provisions a webhook then POSTs a payload to its receive_url.
// Verifies the store returns ok=true and a valid request ID.

func TestE2E_Webhook_ReceiveURL_AcceptsPost(t *testing.T) {
	ip := uniqueIP(t)

	// Probe once to check availability.
	probe := post(t, "/webhook/new", nil, "X-Forwarded-For", ip)
	if probe.StatusCode == http.StatusNotFound || probe.StatusCode == http.StatusServiceUnavailable {
		readBody(t, probe)
		t.Skip("webhook service not enabled — skipping receive test")
	}
	if probe.StatusCode != http.StatusCreated {
		t.Fatalf("POST /webhook/new: want 201, got %d\n%s", probe.StatusCode, readBody(t, probe))
	}

	var provision webhookProvisionResponse
	decodeJSON(t, probe, &provision)

	if provision.Token == "" {
		t.Fatal("provision: got empty token")
	}

	// Extract just the path from the receive_url to use with our test helpers.
	// receive_url is like "https://instant.dev/webhook/receive/<token>" —
	// the test helpers prepend E2E_BASE_URL, so we strip the host.
	receivePath := "/webhook/receive/" + provision.Token

	// POST a test payload to the receive_url.
	payload := map[string]any{
		"event": "test.webhook",
		"data":  map[string]any{"key": "value"},
	}
	recvResp := post(t, receivePath, payload)

	if recvResp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: want 200, got %d\n%s", receivePath, recvResp.StatusCode, readBody(t, recvResp))
	}

	var recvBody struct {
		OK bool   `json:"ok"`
		ID string `json:"id"`
	}
	decodeJSON(t, recvResp, &recvBody)

	if !recvBody.OK {
		t.Error("receive response: ok must be true")
	}
	if recvBody.ID == "" {
		t.Error("receive response: id must not be empty")
	}
	if _, err := uuid.Parse(recvBody.ID); err != nil {
		t.Errorf("receive response: id %q must be a valid UUID: %v", recvBody.ID, err)
	}
}

// ── TestE2E_Webhook_Dedup ─────────────────────────────────────────────────────
//
// Only runs when webhook IS enabled.
// Provisions 6 webhooks from the same fingerprint (same /24 subnet) and asserts
// the 6th call returns an existing token rather than creating a new one.

func TestE2E_Webhook_Dedup(t *testing.T) {
	// Probe once to check availability.
	probe := post(t, "/webhook/new", nil, "X-Forwarded-For", uniqueIP(t))
	if probe.StatusCode == http.StatusNotFound || probe.StatusCode == http.StatusServiceUnavailable {
		readBody(t, probe)
		t.Skip("webhook service not enabled — skipping dedup test")
	}
	var probeBody webhookProvisionResponse
	decodeJSON(t, probe, &probeBody)

	// All 6 provisions share one /24 subnet → same fingerprint.
	// uniqueSubnet guarantees no collision with other tests in this run.
	sharedIP := uniqueSubnet(t).IP(1)

	var seen []string
	for i := 0; i < 5; i++ {
		r := post(t, "/webhook/new", nil, "X-Forwarded-For", sharedIP)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("provision %d: want 201, got %d\n%s", i+1, r.StatusCode, readBody(t, r))
		}
		var b webhookProvisionResponse
		decodeJSON(t, r, &b)
		seen = append(seen, b.Token)
	}

	// 6th call — must return an existing token (fail-open dedup), not a new one.
	r6 := post(t, "/webhook/new", nil, "X-Forwarded-For", sharedIP)
	if r6.StatusCode != http.StatusOK && r6.StatusCode != http.StatusCreated {
		t.Fatalf("6th provision: want 200 or 201, got %d\n%s", r6.StatusCode, readBody(t, r6))
	}
	var body6 webhookProvisionResponse
	decodeJSON(t, r6, &body6)

	existingSet := make(map[string]bool, len(seen))
	for _, tok := range seen {
		existingSet[tok] = true
	}
	if !existingSet[body6.Token] {
		t.Errorf("6th provision must return an existing token; got new token %q (seen: %v)", body6.Token, seen)
	}
}
