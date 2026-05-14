//go:build e2e

// Customer Flow — End-to-end regression test for the full claimed-customer journey.
//
// Codifies the manual customer flow that was hand-driven to verify the
// instanode.dev funnel works end-to-end:
//
//	anonymous /db/new
//	  → /claim (with email)
//	  → session_token returned in body
//	  → /api/v1/whoami    (auth probe; tier=hobby)
//	  → /api/v1/billing   (subscription_status=none; hobby is paid from day one
//	                       per project_no_trial_pay_day_one.md — no trial)
//	  → /api/v1/resources (resource visible at tier=hobby)
//	  → /razorpay/webhook subscription.charged → tier=pro
//	  → /api/v1/billing reflects pro/active
//	  → /api/v1/resources elevated to tier=pro
//	  → /razorpay/webhook subscription.cancelled → tier=hobby (DOWNGRADE)
//	  → existing resources KEEP tier=pro (snapshot — documented CLAUDE.md behaviour)
//
// Plus two adjacent regression tests that fell out of the manual session:
//
//   - /whoami with an anonymous upgrade_jwt MUST 401 (the upgrade_jwt is not
//     a session token; conflating the two would let anonymous tokens auth
//     against the dashboard surface).
//   - /storage/new returns S3-compatible credentials with an endpoint that
//     does NOT contain "minio" (post-Spaces/R2 switch sanity check).
//
// Required env (each test t.Skip()s cleanly when absent):
//
//	E2E_BASE_URL                  live server (default: http://localhost:32108)
//	E2E_JWT_SECRET                signing secret for the session JWT (the test
//	                              uses the session_token minted by /claim, but
//	                              this env var is still required because the
//	                              ambient helpers — getAuthMe etc. — need a
//	                              fallback path and the test compares against it.)
//	E2E_RAZORPAY_WEBHOOK_SECRET   HMAC key for the Razorpay webhook payloads
//	E2E_RAZORPAY_PLAN_ID_PRO      plan_id used in subscription.charged notes
//	                              (optional — handler defaults to "pro" when empty)
package e2e

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// razorpayPlanIDPro returns the Pro plan_id from the environment.
// Empty string is acceptable — the billing webhook handler defaults to "pro"
// when the plan_id is not recognised, so an unconfigured environment still
// exercises the upgrade path. We keep this as a separate helper so a future
// test can require a real plan_id by calling t.Skip() on empty.
func razorpayPlanIDPro() string {
	return strings.TrimSpace(os.Getenv("E2E_RAZORPAY_PLAN_ID_PRO"))
}

// fullClaimResponse mirrors the full POST /claim response — including the
// session_token that the existing claimResponse helper omits. We want to
// exercise the real session_token path here rather than minting our own JWT
// (which is what claimAndGetSession does via makeSessionJWTWithUser).
type fullClaimResponse struct {
	OK           bool   `json:"ok"`
	TeamID       string `json:"team_id"`
	UserID       string `json:"user_id"`
	SessionToken string `json:"session_token"`
	Message      string `json:"message"`
}

// TestE2E_FullCustomerFlow_AnonymousToProToCancelled walks the entire happy
// path: anonymous provision → claim → /whoami → /billing → /resources →
// upgrade webhook → tier elevation → cancel webhook → downgrade. Each step
// asserts the documented contract from CLAUDE.md.
//
// This is the single most important regression test for the customer funnel:
// if this test fails, a paying customer cannot get from "agent provisions"
// to "I am a Pro customer" without manual intervention.
func TestE2E_FullCustomerFlow_AnonymousToProToCancelled(t *testing.T) {
	// All three env vars are required to drive the full flow. We skip rather
	// than fail so the test runs cleanly in environments where Razorpay isn't
	// wired up (local dev with no RAZORPAY_WEBHOOK_SECRET, for example).
	secret := razorpayWebhookSecret(t)
	if os.Getenv("E2E_JWT_SECRET") == "" {
		t.Skip("E2E_JWT_SECRET not set — skipping full customer flow")
	}

	// ── Step 1: anonymous Postgres provision ────────────────────────────────
	ip := uniqueIP(t)
	provResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if provResp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, provResp)
		t.Skip("POST /db/new: service not enabled (503) — skipping full customer flow")
	}
	if provResp.StatusCode != http.StatusCreated {
		t.Fatalf("step 1: POST /db/new: want 201, got %d\n%s", provResp.StatusCode, readBody(t, provResp))
	}
	// Decode into a permissive map so we can grab upgrade_jwt without changing
	// the shared provisionNewResponse type.
	var provBody map[string]any
	decodeJSON(t, provResp, &provBody)

	resourceToken, _ := provBody["token"].(string)
	upgradeJWT, _ := provBody["upgrade_jwt"].(string)
	if resourceToken == "" {
		t.Fatal("step 1: provisioning response missing 'token'")
	}
	if upgradeJWT == "" {
		// Some older response paths only put the JWT in `note`. Fall back rather
		// than fail — that's a different test's job to police.
		if note, _ := provBody["note"].(string); note != "" {
			upgradeJWT = extractJWTFromNote(t, note)
		}
	}
	if upgradeJWT == "" {
		t.Fatal("step 1: could not obtain upgrade_jwt from /db/new response")
	}
	if tier, _ := provBody["tier"].(string); tier != "anonymous" {
		t.Errorf("step 1: anonymous provision tier: want anonymous, got %q", tier)
	}

	// ── Step 2: claim with a randomized email ───────────────────────────────
	email := uniqueEmail()
	teamName := "e2e-flow-" + uuid.NewString()[:6]
	claimResp := post(t, "/claim", map[string]any{
		"jwt":       upgradeJWT,
		"email":     email,
		"team_name": teamName,
	})
	if claimResp.StatusCode != http.StatusCreated {
		t.Fatalf("step 2: POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim fullClaimResponse
	decodeJSON(t, claimResp, &claim)
	if !claim.OK {
		t.Error("step 2: POST /claim: ok must be true")
	}
	if claim.SessionToken == "" {
		t.Fatal("step 2: POST /claim: session_token must be returned (the entire customer flow depends on this)")
	}
	if claim.TeamID == "" {
		t.Fatal("step 2: POST /claim: team_id must be returned")
	}
	if _, err := uuid.Parse(claim.TeamID); err != nil {
		t.Errorf("step 2: team_id %q must be a UUID: %v", claim.TeamID, err)
	}
	t.Logf("step 2: claimed team_id=%s user_id=%s session_token=%d bytes",
		claim.TeamID, claim.UserID, len(claim.SessionToken))

	auth := "Bearer " + claim.SessionToken

	// ── Step 3: /whoami with the session token ──────────────────────────────
	whoamiResp := get(t, "/api/v1/whoami", "Authorization", auth)
	if whoamiResp.StatusCode != http.StatusOK {
		t.Fatalf("step 3: GET /api/v1/whoami: want 200, got %d\n%s", whoamiResp.StatusCode, readBody(t, whoamiResp))
	}
	var whoami map[string]any
	decodeJSON(t, whoamiResp, &whoami)
	if tier, _ := whoami["tier"].(string); tier != "hobby" {
		t.Errorf("step 3: /whoami tier: want hobby, got %q", tier)
	}
	if planTier, _ := whoami["plan_tier"].(string); planTier != "hobby" {
		t.Errorf("step 3: /whoami plan_tier alias: want hobby, got %q", planTier)
	}
	if got, _ := whoami["email"].(string); got != email {
		t.Errorf("step 3: /whoami email: want %q, got %q", email, got)
	}
	if got, _ := whoami["team_id"].(string); got != claim.TeamID {
		t.Errorf("step 3: /whoami team_id: want %q (from claim response), got %q", claim.TeamID, got)
	}

	// ── Step 4: /api/v1/billing — claimed hobby, no subscription yet ────────
	// Per policy memory project_no_trial_pay_day_one.md the platform has no
	// trial period. A freshly-claimed hobby team with no Razorpay subscription
	// reports subscription_status="none" — NOT "trial".
	billingResp := get(t, "/api/v1/billing", "Authorization", auth)
	if billingResp.StatusCode != http.StatusOK {
		t.Fatalf("step 4: GET /api/v1/billing: want 200, got %d\n%s", billingResp.StatusCode, readBody(t, billingResp))
	}
	var billing map[string]any
	decodeJSON(t, billingResp, &billing)
	if tier, _ := billing["tier"].(string); tier != "hobby" {
		t.Errorf("step 4: /billing tier: want hobby, got %q", tier)
	}
	status, _ := billing["subscription_status"].(string)
	if status == "trial" {
		t.Errorf("step 4: /billing subscription_status must never be 'trial' — no trial period exists on the platform")
	}
	if status != "none" {
		t.Errorf("step 4: /billing subscription_status: want none, got %q", status)
	}

	// ── Step 5: /api/v1/resources — claimed resource visible at tier=hobby ─
	listResp := get(t, "/api/v1/resources", "Authorization", auth)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("step 5: GET /api/v1/resources: want 200, got %d\n%s", listResp.StatusCode, readBody(t, listResp))
	}
	var listBody struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp, &listBody)
	if len(listBody.Items) == 0 {
		t.Fatalf("step 5: expected at least one resource (the claimed postgres), got 0")
	}

	found := false
	for _, item := range listBody.Items {
		if item["token"] == resourceToken {
			found = true
			if tier, _ := item["tier"].(string); tier != "hobby" {
				t.Errorf("step 5: claimed resource %q tier: want hobby, got %q", resourceToken, tier)
			}
			break
		}
	}
	if !found {
		t.Errorf("step 5: claimed resource %q not in resource list", resourceToken)
	}

	// ── Step 6: subscription.charged webhook → tier flips to pro ────────────
	planID := razorpayPlanIDPro()
	subID := "sub_test_" + uuid.NewString()[:12]
	chargedPayload := subscriptionChargedPayload(claim.TeamID, subID, planID)

	chargedResp := postRazorpayWebhook(t, secret, chargedPayload)
	chargedBody := readBody(t, chargedResp)
	if chargedResp.StatusCode != http.StatusOK {
		t.Fatalf("step 6: POST /razorpay/webhook (subscription.charged): want 200, got %d\n%s",
			chargedResp.StatusCode, chargedBody)
	}
	if !strings.Contains(chargedBody, `"ok":true`) {
		t.Errorf("step 6: subscription.charged response must contain ok:true; got %s", chargedBody)
	}

	// Razorpay webhook handler updates the DB synchronously, but the test still
	// allows a small window for any read-replica / connection-pool lag.
	time.Sleep(250 * time.Millisecond)

	// ── Step 7: /api/v1/billing reflects pro/active ─────────────────────────
	billingResp2 := get(t, "/api/v1/billing", "Authorization", auth)
	if billingResp2.StatusCode != http.StatusOK {
		t.Fatalf("step 7: GET /api/v1/billing (after upgrade): want 200, got %d\n%s",
			billingResp2.StatusCode, readBody(t, billingResp2))
	}
	var billing2 map[string]any
	decodeJSON(t, billingResp2, &billing2)
	if tier, _ := billing2["tier"].(string); tier != "pro" {
		t.Errorf("step 7: /billing tier after upgrade: want pro, got %q", tier)
	}
	if status, _ := billing2["subscription_status"].(string); status != "active" {
		t.Errorf("step 7: /billing subscription_status after upgrade: want active, got %q", status)
	}

	// ── Step 8: /api/v1/resources — all items elevated to tier=pro ──────────
	listResp2 := get(t, "/api/v1/resources", "Authorization", auth)
	if listResp2.StatusCode != http.StatusOK {
		t.Fatalf("step 8: GET /api/v1/resources (after upgrade): want 200, got %d\n%s",
			listResp2.StatusCode, readBody(t, listResp2))
	}
	var listBody2 struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp2, &listBody2)
	for _, item := range listBody2.Items {
		tier, _ := item["tier"].(string)
		// Skip non-active (deleted/expired) resources — the elevation only
		// applies to active, permanent rows. The list endpoint may still
		// surface them with their old tier.
		if status, _ := item["status"].(string); status != "active" {
			continue
		}
		if tier != "pro" {
			t.Errorf("step 8: post-upgrade, active resource %v tier: want pro, got %q (ElevateResourceTiersByTeam should have promoted it)",
				item["token"], tier)
		}
	}

	// ── Step 9: subscription.cancelled webhook → tier downgrades to hobby ───
	cancelPayload := subscriptionCancelledPayload(claim.TeamID, subID)
	cancelResp := postRazorpayWebhook(t, secret, cancelPayload)
	cancelBody := readBody(t, cancelResp)
	if cancelResp.StatusCode != http.StatusOK {
		t.Fatalf("step 9: POST /razorpay/webhook (subscription.cancelled): want 200, got %d\n%s",
			cancelResp.StatusCode, cancelBody)
	}
	time.Sleep(250 * time.Millisecond)

	// ── Step 10: /api/v1/billing reflects downgrade ─────────────────────────
	billingResp3 := get(t, "/api/v1/billing", "Authorization", auth)
	if billingResp3.StatusCode != http.StatusOK {
		t.Fatalf("step 10: GET /api/v1/billing (after downgrade): want 200, got %d\n%s",
			billingResp3.StatusCode, readBody(t, billingResp3))
	}
	var billing3 map[string]any
	decodeJSON(t, billingResp3, &billing3)
	if tier, _ := billing3["tier"].(string); tier != "hobby" {
		t.Errorf("step 10: /billing tier after cancel: want hobby, got %q", tier)
	}

	// ── Step 11: existing resources KEEP their pro tier (snapshot behaviour) ─
	// Per CLAUDE.md "Downgrade webhook" section:
	//   "Existing resources keep their current tier (user benefit — keeps pro
	//    limits on old resources). New provisions: resource.tier = 'hobby'."
	listResp3 := get(t, "/api/v1/resources", "Authorization", auth)
	if listResp3.StatusCode != http.StatusOK {
		t.Fatalf("step 11: GET /api/v1/resources (after downgrade): want 200, got %d\n%s",
			listResp3.StatusCode, readBody(t, listResp3))
	}
	var listBody3 struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listResp3, &listBody3)
	keptProCount := 0
	for _, item := range listBody3.Items {
		if status, _ := item["status"].(string); status != "active" {
			continue
		}
		if tier, _ := item["tier"].(string); tier == "pro" {
			keptProCount++
		}
	}
	if keptProCount == 0 {
		t.Errorf("step 11: expected existing resources to KEEP tier=pro after downgrade " +
			"(documented user benefit per CLAUDE.md Downgrade webhook section); " +
			"none of the active resources are still pro")
	}
	t.Logf("step 11: %d active resource(s) kept tier=pro after downgrade (correct per docs)", keptProCount)

	t.Logf("FullCustomerFlow: all 11 steps passed for team=%s email=%s", claim.TeamID, email)
}

// TestE2E_FullCustomerFlow_WhoamiBeforeClaim verifies that the anonymous
// upgrade_jwt minted by a provisioning call cannot be used as a session token
// against the dashboard API. The upgrade_jwt is purpose-bound to /claim; if
// the auth middleware accepted it, anonymous tokens would gain access to
// authenticated endpoints — a privilege-escalation bug.
func TestE2E_FullCustomerFlow_WhoamiBeforeClaim(t *testing.T) {
	ip := uniqueIP(t)
	provResp := post(t, "/db/new", nil, "X-Forwarded-For", ip)
	if provResp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, provResp)
		t.Skip("POST /db/new: service not enabled (503)")
	}
	if provResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /db/new: want 201, got %d\n%s", provResp.StatusCode, readBody(t, provResp))
	}
	var provBody map[string]any
	decodeJSON(t, provResp, &provBody)

	upgradeJWT, _ := provBody["upgrade_jwt"].(string)
	if upgradeJWT == "" {
		if note, _ := provBody["note"].(string); note != "" {
			upgradeJWT = extractJWTFromNote(t, note)
		}
	}
	if upgradeJWT == "" {
		t.Fatal("could not obtain upgrade_jwt from /db/new response")
	}

	// Attempt to call /whoami using the upgrade_jwt as a session token.
	// This MUST be rejected — the upgrade_jwt has different claims (no uid/tid)
	// and is signed for the onboarding flow only.
	resp := get(t, "/api/v1/whoami", "Authorization", "Bearer "+upgradeJWT)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/whoami with anonymous upgrade_jwt: want 401, got %d\n%s",
			resp.StatusCode, readBody(t, resp))
	}
}

// TestE2E_FullCustomerFlow_StoragePathReturnsSpacesCreds verifies the
// post-Spaces-switch contract: /storage/new returns S3-compatible credentials
// and the public endpoint does NOT include the internal "minio" hostname.
//
// This guards against a regression where the response would leak the
// k8s-internal MinIO service hostname to public callers (which is unreachable
// from outside the cluster and exposes deployment internals).
func TestE2E_FullCustomerFlow_StoragePathReturnsSpacesCreds(t *testing.T) {
	ip := uniqueIP(t)
	resp := post(t, "/storage/new", nil, "X-Forwarded-For", ip)
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusServiceUnavailable {
		readBody(t, resp)
		t.Skip("POST /storage/new: route not deployed or service disabled")
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /storage/new: want 201, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}

	var body map[string]any
	decodeJSON(t, resp, &body)

	endpoint, _ := body["endpoint"].(string)
	accessKey, _ := body["access_key_id"].(string)
	secretKey, _ := body["secret_access_key"].(string)
	prefix, _ := body["prefix"].(string)
	connURL, _ := body["connection_url"].(string)

	if endpoint == "" {
		t.Error("storage response missing 'endpoint'")
	}
	if accessKey == "" {
		t.Error("storage response missing 'access_key_id'")
	}
	if secretKey == "" {
		t.Error("storage response missing 'secret_access_key'")
	}
	if prefix == "" {
		t.Error("storage response missing 'prefix'")
	}

	// connection_url should be an http(s)://...bucket... shape that callers
	// can plug into the AWS S3 SDK.
	if !strings.HasPrefix(connURL, "http://") && !strings.HasPrefix(connURL, "https://") {
		t.Errorf("connection_url must be http(s) S3 endpoint shape, got %q", connURL)
	}

	// Post-Spaces switch: the public endpoint must NOT contain "minio" — that
	// would mean we're leaking the in-cluster MinIO hostname to public callers.
	if strings.Contains(strings.ToLower(endpoint), "minio") {
		t.Errorf("storage endpoint must not contain 'minio' (post-Spaces switch sanity check); got %q",
			endpoint)
	}
}
