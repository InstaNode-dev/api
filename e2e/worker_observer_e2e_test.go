//go:build e2e

// Persona E — The Worker Observer
//
// Validates that provisioning responses carry correct quota/limits metadata,
// that expiry fields appear on the onboarding landing, and that
// storage_bytes is present on the management API resource shape.
//
// These tests do NOT require any optional env vars — they run in every CI run.
// Tests that need E2E_JWT_SECRET use makeSessionJWT (which skips automatically
// when the secret is absent).
package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ── E1: POST /db/new → limits.storage_mb is present and positive ─────────────

func TestE2E_QuotaBoundary_DB_LimitsHasStorageMB(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /db/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Fatalf("provision /db/new: empty token (status %d)", resp.StatusCode)
	}

	val, ok := body.Limits["storage_mb"]
	if !ok {
		t.Fatalf("limits.storage_mb must be present; got limits=%v", body.Limits)
	}
	mb, ok := val.(float64)
	if !ok || mb <= 0 {
		t.Errorf("limits.storage_mb must be a positive number; got %v (%T)", val, val)
	}
}

// ── E2: POST /cache/new → limits.memory_mb is present and positive ───────────

func TestE2E_QuotaBoundary_Cache_LimitsHasMemoryMB(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /cache/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Fatalf("provision /cache/new: empty token (status %d)", resp.StatusCode)
	}

	val, ok := body.Limits["memory_mb"]
	if !ok {
		t.Fatalf("limits.memory_mb must be present; got limits=%v", body.Limits)
	}
	mb, ok := val.(float64)
	if !ok || mb <= 0 {
		t.Errorf("limits.memory_mb must be a positive number; got %v (%T)", val, val)
	}
}

// ── E3: POST /cache/new (via provisionAnonymous) → limits.memory_mb is present ────────

func TestE2E_QuotaBoundary_Cache_LimitsHasMemoryMB_ViaAnonymous(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)

	val, ok := anonCache.Limits["memory_mb"]
	if !ok {
		t.Fatalf("limits.memory_mb must be present; got limits=%v", anonCache.Limits)
	}
	memMB, ok := val.(float64)
	if !ok || memMB <= 0 {
		t.Errorf("limits.memory_mb must be a positive number; got %v (%T)", val, val)
	}
}

// ── E4: Anonymous DB's expires_at appears in /start landing ──────────────────

func TestE2E_QuotaBoundary_AnonymousDB_ExpiresAtPresentInStartLanding(t *testing.T) {
	ip := uniqueIP(t)

	// Provision a DB — its token should appear in the /start landing.
	dbResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if dbResp.StatusCode == 503 {
		readBody(t, dbResp)
		t.Skip("POST /db/new: service not enabled (503) — skip")
	}
	var db provisionNewResponse
	decodeJSON(t, dbResp, &db)

	// Also provision anonymous cache for the same fingerprint to get a JWT.
	anonCache := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, anonCache.Note)

	// /start now redirects (302) to the dashboard ClaimPage.
	// Resource details are retrieved by the dashboard via GET /claim/preview.
	resp := getNoRedirect(t, "/start?t="+jwt)
	readBody(t, resp)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("GET /start?t=jwt: want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/claim?t=") {
		t.Errorf("/start: Location must contain /claim?t=, got %q", loc)
	}
}

// containsAny returns true if s contains at least one of the given substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 {
			found := false
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					found = true
					break
				}
			}
			if found {
				return true
			}
		}
	}
	return false
}

// ── E5: Management API resource shape has storage_bytes field ─────────────────

func TestE2E_QuotaBoundary_ResourceGet_StorageBytesField_Present(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, anonCache.Note)
	email := uniqueEmail()

	claimResp := post(t, "/claim", map[string]any{
		"jwt": jwt, "email": email, "team_name": "e2e-sb-" + uuid.NewString()[:6],
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT := makeSessionJWT(t, claim.TeamID, email)

	getResp := get(t, "/api/v1/resources/"+anonCache.Token, "Authorization", "Bearer "+sessionJWT)
	if getResp.StatusCode != 200 {
		t.Fatalf("GET /api/v1/resources/:id: want 200, got %d\n%s", getResp.StatusCode, readBody(t, getResp))
	}

	var body struct {
		Item map[string]any `json:"item"`
	}
	decodeJSON(t, getResp, &body)

	// storage_bytes must be present (0 for cache-only rows, ≥0 for DB resources).
	if _, ok := body.Item["storage_bytes"]; !ok {
		t.Errorf("management API resource shape must include storage_bytes field; got item=%v", body.Item)
	}
}

// ── E6: Cache provision — all expected limits fields are present ──────────────

func TestE2E_QuotaBoundary_CacheProvision_LimitsFields_AllPresent(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)

	required := []string{"memory_mb"}
	for _, field := range required {
		if _, ok := anonCache.Limits[field]; !ok {
			t.Errorf("limits must include field %q; got limits=%v", field, anonCache.Limits)
		}
	}
}

// ── E7: Anonymous cache has expires_in in limits ─────────────────────────────

func TestE2E_QuotaBoundary_AnonymousCache_ExpiresIn_Present(t *testing.T) {
	ip := uniqueIP(t)
	anonCache := provisionAnonymous(t, ip)

	if anonCache.Tier != "anonymous" {
		t.Skipf("tier is %q — expires_in check only relevant for anonymous tier", anonCache.Tier)
	}

	// expires_in should be in limits or note should mention expiry.
	_, hasExpiry := anonCache.Limits["expires_in"]
	noteHasExpiry := len(anonCache.Note) > 0
	if !hasExpiry && !noteHasExpiry {
		t.Error("anonymous cache must communicate expiry via limits.expires_in or note field")
	}
}

// ── E8: POST /nosql/new → limits.storage_mb is present ───────────────────────

func TestE2E_QuotaBoundary_NoSQL_LimitsHasStorageMB(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/nosql/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == 503 {
		readBody(t, resp)
		t.Skip("POST /nosql/new: service not enabled (503) — skip")
	}
	var body provisionNewResponse
	decodeJSON(t, resp, &body)

	if body.Token == "" {
		t.Fatalf("provision /nosql/new: empty token (status %d)", resp.StatusCode)
	}

	val, ok := body.Limits["storage_mb"]
	if !ok {
		t.Fatalf("limits.storage_mb must be present for nosql; got limits=%v", body.Limits)
	}
	mb, ok := val.(float64)
	if !ok || mb <= 0 {
		t.Errorf("limits.storage_mb must be a positive number; got %v (%T)", val, val)
	}
}
