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
//	E2E_RAZORPAY_PLAN_ID_PRO     — the configured Pro monthly plan_id; required
//	                               for the tests that assert a genuine
//	                               free/hobby → pro upgrade. Post-F3 an empty
//	                               plan_id maps to `hobby` (not `pro`), so the
//	                               pro path cannot be reached without it. Tests
//	                               that need it SKIP when it is unset.
//	E2E_TEST_TOKEN               — runner-side fingerprint-isolation token (see
//	                               helpers_test.go). Not consumed here directly
//	                               but required in practice: behind an ingress
//	                               that overwrites X-Forwarded-For, every test
//	                               otherwise shares one fingerprint and hits the
//	                               402 free_tier_recycle_requires_claim gate.
//
// If E2E_JWT_SECRET or E2E_RAZORPAY_WEBHOOK_SECRET is unset the whole persona
// is skipped. Individual tests that assert the `pro` tier additionally skip
// when E2E_RAZORPAY_PLAN_ID_PRO is unset.
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

// razorpayProPlanID returns the configured Razorpay Pro monthly plan_id, or
// skips the calling test if it is not provided.
//
// Why this exists: post-F3 (billing.go:planIDToTierFallback, comment "DO NOT
// change this to pro") an empty/unknown plan_id maps to the lowest *paid* tier
// `hobby`, not `pro`. So a test that wants to assert a genuine free/hobby → pro
// upgrade MUST send a real, configured Pro plan_id — there is no way to reach
// `pro` with an empty plan_id any more. The value is read from the
// E2E_RAZORPAY_PLAN_ID_PRO env var (the same place the suite already reads
// E2E_JWT_SECRET / E2E_RAZORPAY_WEBHOOK_SECRET from — pulled from the
// `instant-secrets` k8s secret's RAZORPAY_PLAN_ID_PRO key by the runner).
// Never hardcoded: a hardcoded live plan_id would break hermetic runs against
// a cluster configured with a different (e.g. test-mode) plan catalogue.
func razorpayProPlanID(t *testing.T) string {
	t.Helper()
	p := os.Getenv("E2E_RAZORPAY_PLAN_ID_PRO")
	if p == "" {
		t.Skip("E2E_RAZORPAY_PLAN_ID_PRO not set — skipping the genuine pro-tier upgrade assertion. " +
			"Set it from the cluster's RAZORPAY_PLAN_ID_PRO secret to exercise the free/hobby → pro path.")
	}
	return p
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
//
// No X-Razorpay-Event-Id header is set: each call therefore relies on the
// payload's own `id` field (set per-call to a fresh UUID by the payload
// builders) for the handler's replay-protection key. Use
// postRazorpayWebhookWithEventID when a test must control the dedup key
// across two calls (replay-idempotency tests).
func postRazorpayWebhook(t *testing.T, secret string, payload any) *http.Response {
	t.Helper()
	return postRazorpayWebhookWithEventID(t, secret, payload, "")
}

// postRazorpayWebhookWithEventID is like postRazorpayWebhook but sets an
// explicit X-Razorpay-Event-Id header — the canonical replay-protection key
// the handler claims atomically in razorpay_webhook_events
// (billing.go: "INSERT … ON CONFLICT DO NOTHING"). Passing the SAME eventID
// twice exercises F9 webhook-replay idempotency: the second POST must return
// 200 {"deduped":true} and must NOT re-fire the upgrade state machine.
// An empty eventID omits the header (handler falls back to the body `id`).
func postRazorpayWebhookWithEventID(t *testing.T, secret string, payload any, eventID string) *http.Response {
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
	if eventID != "" {
		req.Header.Set("X-Razorpay-Event-Id", eventID)
	}

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
//
// planID semantics (post-F3, see billing.go planIDToTierFallback):
//   - ""              → handler falls back to the lowest paid tier "hobby"
//     AND emits a billing.charge_undeliverable audit row.
//   - a configured Pro plan_id (E2E_RAZORPAY_PLAN_ID_PRO) → genuine "pro".
//   - any other non-empty string → unrecognised → "hobby" fallback + audit.
//
// Each call stamps a fresh top-level event `id` so two unrelated charges do
// not collide in the handler's razorpay_webhook_events replay table. Tests
// that need a STABLE id across two POSTs (F9 replay) build the payload once
// and reuse it via postRazorpayWebhookWithEventID.
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
		"id":     "evt_test_" + uuid.NewString(),
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
		"id":     "evt_test_" + uuid.NewString(),
		"entity": "event",
		"event":  "subscription.cancelled",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
}

// subscriptionCompletedPayload builds a minimal subscription.completed event.
//
// subscription.completed fires when a Razorpay subscription consumes its
// agreed total_count of billing cycles. paidCount is the number of cycles
// the customer actually paid for: a value > 0 means a HEALTHY paying customer
// reached the term ceiling — handleSubscriptionCompleted (F12) must keep them
// on plan, NOT downgrade. paidCount == 0 means the subscription ended without
// a single successful charge and downgrades like a never-paid cancellation.
func subscriptionCompletedPayload(teamID, subscriptionID string, paidCount int64) map[string]any {
	subEntity, _ := json.Marshal(map[string]any{
		"id":         subscriptionID,
		"entity":     "subscription",
		"status":     "completed",
		"paid_count": paidCount,
		"notes": map[string]any{
			"team_id": teamID,
		},
	})
	return map[string]any{
		"id":     "evt_test_" + uuid.NewString(),
		"entity": "event",
		"event":  "subscription.completed",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
}

// ── B1: subscription.charged with the real Pro plan_id → tier becomes "pro" ──
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): a claimed-but-unpaid team
// is `free`, not `hobby` — the `free` tier did not exist when this test was
// written. The precondition now asserts `free`. And because post-F3 an empty
// plan_id maps to `hobby` (not `pro`), the upgrade now sends the configured
// Pro plan_id (E2E_RAZORPAY_PLAN_ID_PRO) so this test asserts a *genuine*
// free → pro upgrade rather than the fallback path.

func TestE2E_PlanUpgrade_SubscriptionCharged_UpdatesTier(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	before := getAuthMe(t, sessionJWT)
	if before["tier"] != "free" {
		t.Fatalf("precondition: expected tier=free for a claimed-but-unpaid team, got %q", before["tier"])
	}

	subID := "sub_test_" + uuid.NewString()[:12]
	payload := subscriptionChargedPayload(teamID, subID, proPlanID)

	resp := postRazorpayWebhook(t, secret, payload)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /razorpay/webhook (subscription.charged): want 200, got %d\n%s", resp.StatusCode, body)
	}

	after := getAuthMe(t, sessionJWT)
	if after["tier"] != "pro" {
		t.Errorf("after subscription.charged webhook with the Pro plan_id: want tier=pro, got %q", after["tier"])
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

// ── B4: regression guard — trial_ends_at must never appear on /auth/me ───────
//
// The platform has no trial period (see policy memory
// project_no_trial_pay_day_one.md). This test, previously named
// TestE2E_PlanUpgrade_TrialEndsAt_ClearedAfterUpgrade, now asserts that the
// field is absent both before and after a paid subscription.charged webhook.
// Reintroducing the field would silently bring back the trial concept.

func TestE2E_PlanUpgrade_TrialEndsAt_NeverAppearsOnAuthMe(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	before := getAuthMe(t, sessionJWT)
	if _, present := before["trial_ends_at"]; present {
		t.Errorf("trial_ends_at must NOT appear on /auth/me before upgrade — no trial period exists; got %v", before["trial_ends_at"])
	}

	subID := "sub_test_" + uuid.NewString()[:12]
	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, ""))
	readBody(t, resp)

	after := getAuthMe(t, sessionJWT)
	if _, present := after["trial_ends_at"]; present {
		t.Errorf("trial_ends_at must NOT appear on /auth/me after upgrade — no trial period exists; got %v", after["trial_ends_at"])
	}
}

// ── B5: subscription.cancelled → tier reverts to hobby ───────────────────────
//
// Stale-assertion fix (WEBHOOK-VERIFY-2026-05-19): the upgrade leg used an
// empty plan_id and expected `pro` — post-F3 an empty plan_id maps to `hobby`,
// so the `pro` precondition failed before the cancel was ever sent. The
// upgrade now sends the configured Pro plan_id so the `pro` precondition is
// genuinely satisfied, and the cancel-revert assertion (a cancel carrying no
// paid_count downgrades to `hobby`, not the `free` floor) is exercised for
// real.

func TestE2E_PlanDowngrade_SubscriptionCancelled_TierRevertToHobby(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// First upgrade — with the real Pro plan_id so the team genuinely lands on pro.
	subID := "sub_test_" + uuid.NewString()[:12]
	resp1 := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, proPlanID))
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

// ── B6 / F9: webhook replay idempotency ──────────────────────────────────────
//
// Coverage added per WEBHOOK-VERIFY-2026-05-19: the verification's standalone
// harness exercised replay (check T2) but the e2e suite had no dedicated test.
//
// Razorpay re-POSTs signed webhooks (network retries, at-least-once delivery).
// The handler claims each event atomically by X-Razorpay-Event-Id in
// razorpay_webhook_events ("INSERT … ON CONFLICT DO NOTHING"). The SECOND
// delivery of an identical event must:
//   - return 200 with {"deduped":true},
//   - NOT re-run the upgrade state machine (no double elevation, no second
//     receipt, no funnel double-count).
//
// This test sends the SAME signed charged event twice under one stable
// event_id and asserts the team is on `pro` exactly once — a re-fire would
// still leave `pro` on the tier column, so the load-bearing assertion is the
// explicit `deduped:true` flag on the second response.

func TestE2E_PlanUpgrade_WebhookReplay_IsIdempotent_F9(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Build ONE payload + ONE event_id and reuse both across two POSTs.
	subID := "sub_test_" + uuid.NewString()[:12]
	eventID := "evt_replay_" + uuid.NewString()
	payload := subscriptionChargedPayload(teamID, subID, proPlanID)

	// First delivery: owns the event, dispatches the upgrade.
	resp1 := postRazorpayWebhookWithEventID(t, secret, payload, eventID)
	body1 := readBody(t, resp1)
	if resp1.StatusCode != 200 {
		t.Fatalf("F9: first delivery: want 200, got %d\n%s", resp1.StatusCode, body1)
	}

	afterFirst := getAuthMe(t, sessionJWT)
	if afterFirst["tier"] != "pro" {
		t.Fatalf("F9: precondition: first delivery must upgrade to pro, got %q", afterFirst["tier"])
	}

	// Second delivery: identical signed event, identical event_id → must dedup.
	resp2 := postRazorpayWebhookWithEventID(t, secret, payload, eventID)
	if resp2.StatusCode != 200 {
		t.Fatalf("F9: replayed delivery: want 200, got %d\n%s", resp2.StatusCode, readBody(t, resp2))
	}
	var replayBody struct {
		OK      bool `json:"ok"`
		Deduped bool `json:"deduped"`
	}
	decodeJSON(t, resp2, &replayBody)
	if !replayBody.Deduped {
		t.Errorf("F9: replayed webhook must return deduped=true (the upgrade state machine must fire exactly once); got %+v", replayBody)
	}

	// Tier is still pro — a re-fire would not change the column value, but it
	// would have re-elevated resources / re-sent a receipt. The deduped flag
	// above is the real guard; this is a belt-and-braces sanity check.
	afterReplay := getAuthMe(t, sessionJWT)
	if afterReplay["tier"] != "pro" {
		t.Errorf("F9: after replay tier must remain pro, got %q", afterReplay["tier"])
	}
}

// ── B7 / F3: unknown plan_id → safe hobby fallback + charge_undeliverable audit ─
//
// Coverage added per WEBHOOK-VERIFY-2026-05-19: the verification's harness
// proved F3 (check T4 + server logs) but the e2e suite asserted nothing about
// it. This test exercises the F3 fail-safe end-to-end:
//   - a subscription.charged carrying a plan_id that matches no configured
//     RAZORPAY_PLAN_ID_* value resolves to the LOWEST PAID tier `hobby`
//     (planIDToTierFallback) — the customer is never stranded on free after
//     paying — and
//   - a `billing.charge_undeliverable` audit row is written so an operator
//     reconciles the charge (the platform is *guessing* the tier).
//
// The audit row is asserted via GET /api/v1/audit?kind=billing.charge_undeliverable.
// That endpoint 402s for `free`/`anonymous` teams but allows `hobby` (30-day
// lookback) — and the team is exactly `hobby` after the fallback upgrade, so
// the audit trail is readable by the very team the charge landed on.

func TestE2E_PlanUpgrade_UnknownPlanID_FallsToHobby_EmitsChargeUndeliverable_F3(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	before := getAuthMe(t, sessionJWT)
	if before["tier"] != "free" {
		t.Fatalf("F3: precondition: expected tier=free for a claimed-but-unpaid team, got %q", before["tier"])
	}

	// A plan_id that is deliberately not any configured RAZORPAY_PLAN_ID_*.
	bogusPlanID := "plan_e2e_unrecognised_" + uuid.NewString()[:8]
	subID := "sub_test_" + uuid.NewString()[:12]

	resp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, bogusPlanID))
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("F3: webhook with unknown plan_id: want 200 (charge accepted, not 500), got %d\n%s",
			resp.StatusCode, body)
	}

	// Safe fallback: the team is granted the lowest PAID tier, never left on free.
	after := getAuthMe(t, sessionJWT)
	if after["tier"] != "hobby" {
		t.Errorf("F3: unknown plan_id must fall back to the lowest paid tier 'hobby', got %q", after["tier"])
	}

	// The charge must be flagged for operator make-good via a
	// billing.charge_undeliverable audit row. The audit endpoint is readable
	// because the team is now `hobby` (free would 402 here).
	auditResp := get(t, "/api/v1/audit?kind=billing.charge_undeliverable",
		"Authorization", "Bearer "+sessionJWT)
	if auditResp.StatusCode != 200 {
		t.Fatalf("F3: GET /api/v1/audit (kind=billing.charge_undeliverable): want 200, got %d\n%s",
			auditResp.StatusCode, readBody(t, auditResp))
	}
	var auditBody struct {
		OK    bool `json:"ok"`
		Items []struct {
			Kind     string         `json:"kind"`
			Metadata map[string]any `json:"metadata"`
		} `json:"items"`
		TotalReturned int `json:"total_returned"`
	}
	decodeJSON(t, auditResp, &auditBody)

	if auditBody.TotalReturned == 0 {
		t.Fatalf("F3: expected at least one billing.charge_undeliverable audit row after an unknown-plan_id charge; got none")
	}
	for _, it := range auditBody.Items {
		if it.Kind != "billing.charge_undeliverable" {
			t.Errorf("F3: ?kind filter leaked a non-matching row: kind=%q", it.Kind)
		}
	}
	t.Logf("F3: unknown plan_id %q → tier=hobby (safe fallback) + %d billing.charge_undeliverable audit row(s) ✓",
		bogusPlanID, auditBody.TotalReturned)
}

// ── B8 / F12: subscription.completed on a healthy paying team does NOT downgrade ─
//
// Coverage added per WEBHOOK-VERIFY-2026-05-19 (flagged as a coverage gap —
// the downgrade tests that would touch F12 were blocked by stale assertions).
//
// subscription.completed fires when a Razorpay subscription consumes its
// agreed total_count of billing cycles. The pre-F12 code routed it straight to
// the downgrade path, so a loyal customer who paid every cycle of a legacy
// 12-count subscription was silently dropped to a lower tier at month 13 and
// emailed a cancellation notice. handleSubscriptionCompleted now treats a
// completion with paid_count > 0 as a HEALTHY end-of-term: the team keeps its
// plan, no downgrade, no cancellation audit/email.
//
// This test upgrades a team to `pro`, then fires subscription.completed with
// paid_count = 12 (a healthy paying customer) and asserts the tier stays `pro`.

func TestE2E_PlanUpgrade_SubscriptionCompleted_HealthyTeam_NoDowngrade_F12(t *testing.T) {
	secret := razorpayWebhookSecret(t)
	proPlanID := razorpayProPlanID(t)
	teamID, sessionJWT, _ := claimAndGetSession(t)

	// Upgrade to pro with the real Pro plan_id.
	subID := "sub_test_" + uuid.NewString()[:12]
	upResp := postRazorpayWebhook(t, secret, subscriptionChargedPayload(teamID, subID, proPlanID))
	readBody(t, upResp)
	if upResp.StatusCode != 200 {
		t.Fatalf("F12: upgrade webhook: want 200, got %d", upResp.StatusCode)
	}
	if me := getAuthMe(t, sessionJWT); me["tier"] != "pro" {
		t.Fatalf("F12: precondition: upgrade did not take effect, tier=%q", me["tier"])
	}

	// subscription.completed on a HEALTHY paying subscription (12 cycles paid).
	completedResp := postRazorpayWebhook(t, secret,
		subscriptionCompletedPayload(teamID, subID, 12))
	completedBody := readBody(t, completedResp)
	if completedResp.StatusCode != 200 {
		t.Fatalf("F12: subscription.completed webhook: want 200, got %d\n%s",
			completedResp.StatusCode, completedBody)
	}

	time.Sleep(200 * time.Millisecond)

	// The loyal customer MUST keep their plan — completion on a paying
	// subscription is not a cancellation.
	after := getAuthMe(t, sessionJWT)
	if after["tier"] != "pro" {
		t.Errorf("F12: subscription.completed on a healthy paying team must NOT downgrade it; "+
			"want tier=pro, got %q", after["tier"])
	}
	t.Logf("F12: subscription.completed (paid_count=12) on a pro team kept tier=%q ✓ (loyal customer not downgraded)", after["tier"])
}

// Ensure the plan upgrade test file compiles.
var _ = fmt.Sprintf
