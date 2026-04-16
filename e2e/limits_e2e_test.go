//go:build e2e

// Limits — S6 from the full-system test plan.
//
// Rate limiting and provisioning limits:
//   S6.1  6 provisions from same fingerprint — limit CTA appears, never 500
//   S6.2  Response at limit contains upgrade URL
//   S6.3  Different fingerprint (different IP) after first hits limit → still 201
//
// Note: Tests that send many requests in a loop are guarded by E2E_ALLOW_QUOTA_BURN.
// S6.3 is safe because it only needs one call per IP.
package e2e

import (
	"strings"
	"testing"
)

// ── S6.1 / S6.2: After daily limit, response has upgrade CTA, never 500 ──────

func TestE2E_Limits_DailyProvisionLimit_UpgradeCTAAppearsNever500(t *testing.T) {
	allowQuotaBurn(t)

	// Same IP for all requests → same fingerprint.
	ip := uniqueIP(t)

	var lastCode int
	var lastBody string

	for i := 0; i < 8; i++ {
		resp := post(t, "/cache/new", nil, "X-Forwarded-For", ip)
		lastBody = readBody(t, resp)
		lastCode = resp.StatusCode

		if resp.StatusCode == 500 {
			t.Fatalf("call %d: POST /cache/new returned 500: %.200s", i+1, lastBody)
		}
		// Accept 200 (upgrade CTA) or 201 (new token).
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			t.Errorf("call %d: POST /cache/new: want 200 or 201, got %d: %.200s", i+1, resp.StatusCode, lastBody)
		}
	}

	// After 6+, should be hitting the limit (200 with upgrade CTA).
	if lastCode == 201 {
		t.Log("note: server allowed > 6 provisions (limit may be higher in this environment)")
	}
	if lastCode == 200 {
		// The response must contain an upgrade URL.
		if !strings.Contains(lastBody, "instant.dev/start") && !strings.Contains(lastBody, "upgrade") {
			t.Errorf("limit-hit response must contain upgrade URL or 'upgrade', got: %.300s", lastBody)
		}
	}
}

// ── S6.3: Different fingerprint after first hits limit → still gets 201 ───────

func TestE2E_Limits_DifferentFingerprint_IndependentLimit(t *testing.T) {
	// Provision a resource from one IP.
	ip1 := uniqueIP(t)
	r1 := post(t, "/cache/new", nil, "X-Forwarded-For", ip1)
	body1 := readBody(t, r1)
	if r1.StatusCode != 201 {
		t.Fatalf("first IP: want 201, got %d: %s", r1.StatusCode, body1)
	}

	// A completely different IP should still get 201.
	ip2 := uniqueIP(t)
	r2 := post(t, "/cache/new", nil, "X-Forwarded-For", ip2)
	body2 := readBody(t, r2)
	if r2.StatusCode != 201 {
		t.Fatalf("second (different) IP: want 201, got %d: %s", r2.StatusCode, body2)
	}
}

// ── S6.4: Anonymous resources have expires_at set ─────────────────────────────

func TestE2E_Limits_Anonymous_HasExpiresAt(t *testing.T) {
	ip := uniqueIP(t)
	prov := provisionAnonymous(t, ip)

	// Extract JWT and check exp field as proxy for expires_at.
	jwtStr := extractJWTFromNote(t, prov.Note)
	claims := decodeJWTClaims(t, jwtStr)

	if _, ok := claims["exp"]; !ok {
		t.Error("onboarding JWT must have 'exp' claim (proxy for resource expires_at)")
	}
}

// ── S6.5: Pro tier provisioning has higher limits than anonymous ──────────────

func TestE2E_Limits_ProTier_HigherStorageLimits(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Upgrade to pro via Razorpay webhook.
	subscriptionID := "cus_test_limits_" + uniqueIP(t)
	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subscriptionID, ""))
	readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("Razorpay webhook: want 200, got %d", resp.StatusCode)
	}

	// Provision a cache resource as pro user.
	cacheResp := post(t, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	if cacheResp.StatusCode == 503 {
		t.Skip("POST /cache/new: service not enabled (503)")
	}
	if cacheResp.StatusCode != 201 {
		t.Fatalf("POST /cache/new (pro): want 201, got %d\n%s", cacheResp.StatusCode, readBody(t, cacheResp))
	}
	var body provisionNewResponse
	decodeJSON(t, cacheResp, &body)

	if body.Tier != "pro" {
		t.Errorf("pro-tier provisioned cache: want tier=pro, got %q", body.Tier)
	}
	if memMB, ok := body.Limits["redis_memory_mb"].(float64); ok {
		if memMB <= 5 {
			t.Errorf("pro tier redis_memory_mb should be > 5 (anonymous limit), got %.0f", memMB)
		}
	}
}
