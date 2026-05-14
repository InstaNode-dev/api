//go:build e2e

package e2e

// w11_anon_internal_url_e2e_test.go — black-box coverage for W11 Fix 1
// (anon internal_url scrub, 2026-05-14).
//
// Contract: POST /<service>/new from an unclaimed (anonymous) caller MUST
// NOT carry `internal_url` in the response body. The cluster-internal
// proxy FQDN leaks infra topology and serves no purpose for anon callers
// — they can't run /deploy/new workloads against the proxy without a
// claimed team. Companion unit coverage lives in
// internal/handlers/internal_url_test.go::TestSetInternalURL.
//
// Target endpoint: /cache/new because redis is the most reliably-enabled
// service in dev (db can skip on 503, nosql can skip on mongo absence).
// The handler returns internal_url via the same setInternalURL helper
// that all four provisioning endpoints share, so a single endpoint
// exercises the contract for the whole family.

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestE2E_W11_AnonProvision_NoInternalURL pins the anon-internal_url
// scrub contract at the HTTP boundary. The response body MUST NOT
// contain an `internal_url` field for an unclaimed POST /cache/new.
func TestE2E_W11_AnonProvision_NoInternalURL(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)

	if resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("/cache/new service not enabled")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /cache/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	body := readBody(t, resp)

	// Parse to a free-form map so we can assert on field presence rather
	// than on a typed struct (which would silently swallow the field).
	var raw map[string]any
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("decode /cache/new body: %v\n%s", err, body)
	}

	if tier, _ := raw["tier"].(string); tier != "anonymous" {
		t.Fatalf("expected tier=anonymous, got %q (full body: %s)", tier, body)
	}
	if _, present := raw["internal_url"]; present {
		t.Errorf("anonymous /cache/new MUST NOT include internal_url; got body:\n%s", body)
	}
	// Sanity: connection_url is still there (we scrubbed internal_url, not the public URL).
	if cu, _ := raw["connection_url"].(string); cu == "" {
		t.Errorf("connection_url must remain populated for anon callers; got body:\n%s", body)
	}
}
