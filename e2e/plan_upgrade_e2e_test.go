//go:build e2e

// Persona B — The Plan Upgrader
//
// Simulates a Razorpay subscription.charged completing and a subscription being cancelled.
// Constructs real Razorpay-signed webhook payloads and verifies the tier change
// cascades: GET /auth/me reflects new tier, limits on new provisions change,
// existing resources remain active.
//
// Required env vars:
//
//	E2E_JWT_SECRET               — to sign session JWTs for GET /auth/me
//	E2E_RAZORPAY_WEBHOOK_SECRET  — webhook signing secret from Razorpay dashboard
//
// If either is unset the whole persona is skipped.
package e2e

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// razorpayWebhookSecret returns the Razorpay webhook secret or skips the test.
func razorpayWebhookSecret(t *testing.T) string {
	t.Helper()
	s := os.Getenv("E2E_RAZORPAY_WEBHOOK_SECRET")
	if s == "" {
		t.Skip("E2E_RAZORPAY_WEBHOOK_SECRET not set — skipping Razorpay webhook tests.")
	}
	return s
}

// signRazorpayPayload computes HMAC-SHA256(key=secret, msg=rawBody) as hex.
// Razorpay webhook signature = hex(HMAC-SHA256(webhookSecret, rawBody)).
func signRazorpayPayload(t *testing.T, secret string, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// postRazorpayWebhook sends a signed webhook event to POST /razorpay/webhook.
func postRazorpayWebhook(t *testing.T, secret string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal razorpay payload: %v", err)
	}
	sig := signRazorpayPayload(t, secret, body)

	req, err := http.NewRequest(http.MethodPost, baseURL()+"/razorpay/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest razorpay webhook: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /razorpay/webhook: %v", err)
	}
	return resp
}

// claimAndGetSession provisions an anonymous resource, claims it, and returns (teamID, sessionJWT, email).
func claimAndGetSession(t *testing.T) (teamID, sessionJWT, email string) {
	t.Helper()
	ip := uniqueIP(t)
	resource := provisionAnonymous(t, ip)
	jwt := extractJWTFromNote(t, resource.Note)
	email = uniqueEmail()
	teamName := "e2e-upgrade-" + uuid.NewString()[:6]

	claimResp := post(t, "/claim", map[string]any{
		"jwt":       jwt,
		"email":     email,
		"team_name": teamName,
	})
	if claimResp.StatusCode != 201 {
		t.Fatalf("POST /claim: want 201, got %d\n%s", claimResp.StatusCode, readBody(t, claimResp))
	}
	var claim claimResponse
	decodeJSON(t, claimResp, &claim)

	sessionJWT = makeSessionJWTWithUser(t, claim.UserID, claim.TeamID, email)
	return claim.TeamID, sessionJWT, email
}

// getAuthMe returns the /auth/me response for a session JWT.
func getAuthMe(t *testing.T, sessionJWT string) map[string]any {
	t.Helper()
	resp := get(t, "/auth/me", "Authorization", "Bearer "+sessionJWT)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /auth/me: want 200, got %d\n%s", resp.StatusCode, readBody(t, resp))
	}
	var body map[string]any
	decodeJSON(t, resp, &body)
	return body
}

// subscriptionChargedPayload builds a minimal subscription.charged event.
// The handler reads notes["team_id"] and plan_id to derive tier.
func subscriptionChargedPayload(teamID, subscriptionID, planID string) map[string]any {
	subEntity, _ := json.Marshal(map[string]any{
		"id":      subscriptionID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  "active",
		"notes": map[string]any{
			"team_id": teamID,
		},
	})
	return map[string]any{
		"entity": "event",
		"event":  "subscription.charged",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
}

// subscriptionCancelledPayload builds a minimal subscription.cancelled event.
func subscriptionCancelledPayload(teamID, subscriptionID string) map[string]any {
	subEntity, _ := json.Marshal(map[string]any{
		"id":     subscriptionID,
		"entity": "subscription",
		"status": "cancelled",
		"notes": map[string]any{
			"team_id": teamID,
		},
	})
	return map[string]any{
		"entity": "event",
		"event":  "subscription.cancelled",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
}

// ── B1: subscription.charged → tier becomes "pro" ───────────────────────────

func TestE2E_PlanUpgrade_SubscriptionCharged_UpdatesTier(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	before := getAuthMe(t, sessionJWT)
	if before["tier"] != "hobby" {
		t.Fatalf("precondition: expected tier=hobby before upgrade, got %q", before["tier"])
	}

	subID := "sub_test_" + uuid.NewString()[:12]
	// No planID configured in test env → handler defaults to "pro"
	payload := subscriptionChargedPayload(teamID, subID, "")

	resp := postRazorpayWebhook(t, secret, payload)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /razorpay/webhook (subscription.charged): want 200, got %d\n%s", resp.StatusCode, body)
	}

	after := getAuthMe(t, sessionJWT)
	if after["tier"] != "pro" {
		t.Errorf("after subscription.charged webhook: want tier=pro, got %q", after["tier"])
	}
}

// ── B2: After upgrade, new cache resource has pro-tier limits ────────────────

func TestE2E_PlanUpgrade_NewResource_ReceivesProLimits(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, email := claimAndGetSession(t)

	subID := "sub_test_" + uuid.NewString()[:12]
	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, ""))
	readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("webhook: want 200, got %d", resp.StatusCode)
	}

	cacheResp := post(t, "/cache/new", nil,
		"X-Forwarded-For", uniqueIP(t),
		"Authorization", "Bearer "+sessionJWT,
	)
	if cacheResp.StatusCode == 503 {
		readBody(t, cacheResp)
		t.Skip("POST /cache/new: service not enabled (503) — skip")
	}
	if cacheResp.StatusCode != 201 {
		t.Fatalf("POST /cache/new (pro auth): want 201, got %d\n%s", cacheResp.StatusCode, readBody(t, cacheResp))
	}
	var cache provisionNewResponse
	decodeJSON(t, cacheResp, &cache)

	_ = email

	if memMB, ok := cache.Limits["memory_mb"].(float64); ok {
		if memMB <= 5 {
			t.Errorf("pro tier cache: want memory_mb > 5, got %.0f", memMB)
		}
	} else {
		t.Errorf("limits.memory_mb must be a number, got %T", cache.Limits["memory_mb"])
	}
}

// ── B3: Pre-upgrade resources remain active after upgrade ────────────────────

func TestE2E_PlanUpgrade_ResourceList_PreviousResourcesStillPresent(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	listBefore := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	var beforeBody struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listBefore, &beforeBody)
	countBefore := len(beforeBody.Items)

	subID := "sub_test_" + uuid.NewString()[:12]
	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, ""))
	readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("webhook: want 200, got %d", resp.StatusCode)
	}

	listAfter := get(t, "/api/v1/resources", "Authorization", "Bearer "+sessionJWT)
	var afterBody struct {
		Items []map[string]any `json:"items"`
	}
	decodeJSON(t, listAfter, &afterBody)

	if len(afterBody.Items) < countBefore {
		t.Errorf("resource count decreased after upgrade: before=%d after=%d", countBefore, len(afterBody.Items))
	}
	for _, item := range afterBody.Items {
		if item["status"] == "deleted" {
			t.Errorf("resource %v was deleted by plan upgrade — must remain active", item["token"])
		}
	}
}

// ── B4: trial_ends_at is cleared after paid subscription.charged ─────────────

func TestE2E_PlanUpgrade_TrialEndsAt_ClearedAfterUpgrade(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	before := getAuthMe(t, sessionJWT)
	if before["trial_ends_at"] == nil {
		t.Log("note: trial_ends_at not set before upgrade (OK if trial already nil)")
	}

	subID := "sub_test_" + uuid.NewString()[:12]
	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, ""))
	readBody(t, resp)

	after := getAuthMe(t, sessionJWT)
	if after["trial_ends_at"] != nil {
		t.Errorf("trial_ends_at must be cleared after subscription.charged; got %v", after["trial_ends_at"])
	}
}

// ── B5: subscription.cancelled → tier reverts to hobby ───────────────────────

func TestE2E_PlanDowngrade_SubscriptionCancelled_TierRevertToHobby(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// First upgrade.
	subID := "sub_test_" + uuid.NewString()[:12]
	resp1 := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, ""))
	readBody(t, resp1)

	after := getAuthMe(t, sessionJWT)
	if after["tier"] != "pro" {
		t.Fatalf("precondition: upgrade did not take effect, tier=%q", after["tier"])
	}

	// Now cancel subscription.
	resp2 := postRazorpayWebhook(t, secret, subscriptionCancelledPayload(teamID, subID))
	body2 := readBody(t, resp2)
	if resp2.StatusCode != 200 {
		t.Fatalf("POST /razorpay/webhook (subscription.cancelled): want 200, got %d\n%s", resp2.StatusCode, body2)
	}

	time.Sleep(100 * time.Millisecond)

	downgraded := getAuthMe(t, sessionJWT)
	if downgraded["tier"] != "hobby" {
		t.Errorf("after subscription.cancelled: want tier=hobby, got %q", downgraded["tier"])
	}
}

// Ensure the plan upgrade test file compiles.
var _ = fmt.Sprintf
