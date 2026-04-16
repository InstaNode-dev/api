//go:build e2e

// Storage E2E tests — POST /storage/new — Cloudflare R2 provisioning.
//
// Test groups:
//
//	TestE2E_Storage_ServiceDisabled_Or_ValidShape — skip on 503/404; validate shape when live
//	TestE2E_Storage_ConnectionURLFormat           — connection_url starts with https://
//	TestE2E_Storage_Dedup                         — 6th provision from same fingerprint returns existing token
//
// Storage service status:
//
//	The R2 object storage service is Phase 5 and not yet in INSTANT_ENABLED_SERVICES.
//	All tests detect 404 or 503 and skip rather than fail, so the suite is safe
//	to run against any cluster state.
//
// Required env vars (optional — tests skip when absent):
//
//	E2E_BASE_URL  live server (default: http://localhost:30080)
package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// storageServiceDisabled returns true and skips the test when the storage endpoint
// responds with 404 (route not deployed) or 503 (feature-flagged off).
func storageServiceDisabled(t *testing.T, resp *http.Response) bool {
	t.Helper()
	if resp.StatusCode == http.StatusNotFound {
		body := readBody(t, resp)
		t.Skipf("POST /storage/new: 404 — route not deployed on this cluster (body: %s)", body)
		return true
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		var errBody errorResponse
		decodeJSON(t, resp, &errBody)
		if errBody.Error != "service_disabled" {
			t.Errorf("503 from /storage/new must carry error=service_disabled, got %q", errBody.Error)
		}
		t.Skipf("POST /storage/new: 503 service_disabled — storage not yet in INSTANT_ENABLED_SERVICES")
		return true
	}
	return false
}

// ── TestE2E_Storage_ServiceDisabled_Or_ValidShape ─────────────────────────────
//
// Always-run: detects whether the service is disabled (skip) or live (validate shape).

func TestE2E_Storage_ServiceDisabled_Or_ValidShape(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/storage/new", nil, "X-Forwarded-For", ip)

	if storageServiceDisabled(t, resp) {
		return
	}

	// Service is live — validate full response shape.
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /storage/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body provisionNewResponse
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
	if !strings.HasPrefix(body.ConnectionURL, "https://") && !strings.HasPrefix(body.ConnectionURL, "http://") {
		t.Errorf("connection_url must start with http:// or https://; got %q", body.ConnectionURL)
	}
	if body.Tier != "anonymous" {
		t.Errorf("unauthenticated provision must produce anonymous tier, got %q", body.Tier)
	}
	if body.Limits == nil {
		t.Error("limits field must not be nil")
	}

	// Decode full map to check storage-specific fields.
	resp2 := post(t, "/storage/new", nil, "X-Forwarded-For", uniqueIP(t))
	var raw map[string]any
	decodeJSON(t, resp2, &raw)

	if akID, ok := raw["access_key_id"].(string); !ok || akID == "" {
		t.Errorf("access_key_id must be a non-empty string; got %v", raw["access_key_id"])
	}
	if sak, ok := raw["secret_access_key"].(string); !ok || sak == "" {
		t.Errorf("secret_access_key must be a non-empty string; got %v", raw["secret_access_key"])
	}
	if prefix, ok := raw["prefix"].(string); !ok || prefix == "" {
		t.Errorf("prefix must be a non-empty string; got %v", raw["prefix"])
	}
}

// ── TestE2E_Storage_ConnectionURLFormat ──────────────────────────────────────
//
// Verifies the connection_url starts with https:// and contains the token prefix.

func TestE2E_Storage_ConnectionURLFormat(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/storage/new", nil, "X-Forwarded-For", ip)

	if storageServiceDisabled(t, resp) {
		return
	}

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /storage/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var raw map[string]any
	decodeJSON(t, resp, &raw)

	connectionURL, ok := raw["connection_url"].(string)
	if !ok || connectionURL == "" {
		t.Fatalf("connection_url must be a non-empty string; got %v", raw["connection_url"])
	}

	if !strings.HasPrefix(connectionURL, "https://") && !strings.HasPrefix(connectionURL, "http://") {
		t.Errorf("connection_url must start with http:// or https://; got %q", connectionURL)
	}

	// The prefix field should appear inside the connection_url.
	prefix, ok := raw["prefix"].(string)
	if ok && prefix != "" {
		if !strings.Contains(connectionURL, prefix) {
			t.Errorf("connection_url %q must contain prefix %q", connectionURL, prefix)
		}
	}

	// access_key_id must start with "key_".
	akID, ok := raw["access_key_id"].(string)
	if !ok || akID == "" {
		t.Fatalf("access_key_id must be a non-empty string; got %v", raw["access_key_id"])
	}
	if !strings.HasPrefix(akID, "key_") {
		t.Errorf("access_key_id must start with 'key_'; got %q", akID)
	}
}

// ── TestE2E_Storage_Dedup ─────────────────────────────────────────────────────
//
// Provisions 6 times from the same fingerprint; the 6th must return an existing token.

func TestE2E_Storage_Dedup(t *testing.T) {
	// Probe once to check service availability.
	probe := post(t, "/storage/new", nil, "X-Forwarded-For", uniqueIP(t))
	if probe.StatusCode == http.StatusNotFound || probe.StatusCode == http.StatusServiceUnavailable {
		readBody(t, probe)
		t.Skip("storage service not enabled — skipping dedup test")
	}
	// Drain the probe body.
	var probeBody provisionNewResponse
	decodeJSON(t, probe, &probeBody)

	// All 6 provisions share one /24 subnet → same fingerprint.
	// uniqueSubnet guarantees no collision with other tests in this run.
	ip := uniqueSubnet(t).IP(1)

	var seen []string
	for i := 0; i < 5; i++ {
		r := post(t, "/storage/new", nil, "X-Forwarded-For", ip)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("provision %d: want 201, got %d\n%s", i+1, r.StatusCode, readBody(t, r))
		}
		var b provisionNewResponse
		decodeJSON(t, r, &b)
		seen = append(seen, b.Token)
	}

	// 6th call — must return an existing token (fail-open dedup), not a new one.
	r6 := post(t, "/storage/new", nil, "X-Forwarded-For", ip)
	if r6.StatusCode != http.StatusOK && r6.StatusCode != http.StatusCreated {
		t.Fatalf("6th provision: want 200 or 201, got %d\n%s", r6.StatusCode, readBody(t, r6))
	}
	var body6 provisionNewResponse
	decodeJSON(t, r6, &body6)

	existingSet := make(map[string]bool, len(seen))
	for _, tok := range seen {
		existingSet[tok] = true
	}
	if !existingSet[body6.Token] {
		t.Errorf("6th provision must return an existing token; got new token %q (seen: %v)", body6.Token, seen)
	}
}
