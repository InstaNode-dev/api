package handlers_test

// billing_block_webhook_transitions_test.go — W3 §E4/E5/E6/E7 + checkout
// graceful-failure. The Razorpay webhook is the surface that actually moves a
// team between paid tiers; these are DB-backed integration tests against a
// real test Postgres so the tier mutation and resource elevation land in real
// rows (no mocks on the asserted path).
//
// Covered:
//   - UPGRADE (subscription.charged): elevates teams.plan_tier AND promotes
//     every active resource to the new tier (the ElevateResourceTiersByTeam
//     contract folded into UpgradeTeamAllTiersWithSubscription). §E4 / rule 5.
//   - DOWNGRADE (subscription.cancelled): drops teams.plan_tier to the courtesy
//     floor but LEAVES existing resources at their current tier (UpdatePlanTier
//     only — the deliberate user-benefit asymmetry). §E5 / rule 5.
//   - BAD SIGNATURE: a tampered/forged signature is rejected with 400
//     invalid_signature before any state change. §E6 / rule 9.
//   - ROWS-AFFECTED 0: a signed charged event for an unknown team returns 404
//     team_not_found (ErrTeamNotFound on the 0-row UPDATE). §E7.
//
// Reuses the existing webhook conventions: cov2WebhookAppReal,
// signRazorpayPayload, makeSubscriptionChargedPayloadWithPlan,
// makeSubscriptionCancelledPayload. Nothing redefined.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
)

// postSignedWebhook signs payload with the canonical test webhook secret and
// POSTs it, returning the HTTP status + decoded JSON body. eventID, when
// non-empty, is set on the X-Razorpay-Event-Id header (the dedup claim key).
func postSignedWebhook(t *testing.T, app *fiber.App, payload []byte, eventID string) (int, map[string]any) {
	t.Helper()
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	if eventID != "" {
		req.Header.Set("X-Razorpay-Event-Id", eventID)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// billingBlockRespMap decodes an *http.Response JSON body into a map.
func billingBlockRespMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body
}

// TestBillingBlock_WebhookUpgrade_ElevatesTierAndResources — §E4. A signed
// subscription.charged event with a Pro plan_id must (a) flip the team's
// plan_tier to pro and (b) promote every active resource the team owns to pro.
// The resources start at 'free' (a just-claimed team) and must end at 'pro' —
// proving ElevateResourceTiersByTeam ran inside the upgrade tx.
func TestBillingBlock_WebhookUpgrade_ElevatesTierAndResources(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	teamIDStr := mustSeedTeam(t, db, "free")
	teamID := uuid.MustParse(teamIDStr)

	// Two active resources at the free tier — the rows that must be elevated.
	dbRes := billingBlockSeedResource(t, db, teamID, "postgres", "free")
	cacheRes := billingBlockSeedResource(t, db, teamID, "redis", "free")

	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	subID := "sub_upgrade_" + uuid.NewString()
	eventID := "evt_upgrade_" + uuid.NewString()
	payload := makeSubscriptionChargedPayloadWithPlan(t, teamIDStr, subID, cfg.RazorpayPlanIDPro)

	status, body := postSignedWebhook(t, app, payload, eventID)
	require.Equal(t, http.StatusOK, status, "charged webhook must 200 on a known team, body=%v", body)

	// Team tier elevated.
	assert.Equal(t, "pro", billingBlockTeamTier(t, db, teamIDStr),
		"subscription.charged with a Pro plan_id must set teams.plan_tier=pro")

	// ALL active resources promoted (rule 5: upgrade elevates active resources).
	assert.Equal(t, "pro", billingBlockResourceTier(t, db, dbRes),
		"upgrade must promote the postgres resource from free → pro (ElevateResourceTiersByTeam)")
	assert.Equal(t, "pro", billingBlockResourceTier(t, db, cacheRes),
		"upgrade must promote the redis resource from free → pro (ElevateResourceTiersByTeam)")

	// Cleanup the dedup claim row so a re-run can re-process the same event id.
	db.Exec(`DELETE FROM razorpay_webhook_events WHERE event_id = $1`, eventID)
}

// TestBillingBlock_WebhookDowngrade_KeepsResourceTiers — §E5. A signed
// subscription.cancelled event for the team's LIVE subscription drops the
// team's plan_tier to the courtesy floor (hobby) but must LEAVE existing
// resources at their current (pro) tier — the deliberate user-benefit
// asymmetry (UpdatePlanTier only, no resource teardown). rule 5.
func TestBillingBlock_WebhookDowngrade_KeepsResourceTiers(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	teamIDStr := mustSeedTeam(t, db, "pro")
	teamID := uuid.MustParse(teamIDStr)

	// A pro resource that must SURVIVE the downgrade at tier=pro.
	proRes := billingBlockSeedResource(t, db, teamID, "postgres", "pro")

	// Store the live subscription id on the team so the cancelled webhook's
	// stale-subscription guard recognises this event as the team's live sub
	// (and proceeds with the downgrade) rather than skipping it as superseded.
	subID := "sub_downgrade_" + uuid.NewString()
	_, err := db.Exec(`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, subID, teamIDStr)
	require.NoError(t, err)

	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	payload := makeSubscriptionCancelledPayload(t, teamIDStr, subID)
	// makeSubscriptionCancelledPayload omits the top-level event id; set one on
	// the header so the dedup claim has a key and we can clean it up.
	eventID := "evt_downgrade_" + uuid.NewString()

	status, body := postSignedWebhook(t, app, payload, eventID)
	require.Equal(t, http.StatusOK, status, "cancelled webhook must 200, body=%v", body)

	// Team dropped to the courtesy floor (paid_count nil → hobby).
	assert.Equal(t, "hobby", billingBlockTeamTier(t, db, teamIDStr),
		"subscription.cancelled (with a prior paid invoice / nil paid_count) drops the team to the hobby courtesy floor")

	// CRITICAL user-benefit invariant: the resource KEEPS its pro tier.
	assert.Equal(t, "pro", billingBlockResourceTier(t, db, proRes),
		"downgrade must NOT touch existing resource tiers — they stay at pro as a customer courtesy (rule 5)")

	db.Exec(`DELETE FROM razorpay_webhook_events WHERE event_id = $1`, eventID)
}

// TestBillingBlock_WebhookBadSignature_Rejected — §E6 / rule 9. A signed body
// with a TAMPERED signature is rejected 400 invalid_signature and must NOT
// mutate the team tier. We post a valid-shape (64-hex) but wrong signature so
// we exercise the constant-time-compare failure, not the length pre-check.
func TestBillingBlock_WebhookBadSignature_Rejected(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	teamIDStr := mustSeedTeam(t, db, "free")
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	subID := "sub_badsig_" + uuid.NewString()
	payload := makeSubscriptionChargedPayloadWithPlan(t, teamIDStr, subID, cfg.RazorpayPlanIDPro)

	// A signature signed with the WRONG secret — correct length (64 hex), fails
	// the HMAC compare.
	wrongSig := signRazorpayPayload(t, "definitely-not-the-webhook-secret", payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", wrongSig)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a bad-signature webhook must be rejected 400 before any state change")
	body := billingBlockRespMap(t, resp)
	assert.Equal(t, "invalid_signature", body["error"],
		"bad-signature rejection must carry the stable invalid_signature code")

	// The team tier must be UNCHANGED — a forged webhook must never upgrade.
	assert.Equal(t, "free", billingBlockTeamTier(t, db, teamIDStr),
		"a rejected forged webhook must not mutate the team tier")
}

// TestBillingBlock_WebhookUnknownTeam_RowsAffectedZero — §E7. A signed
// subscription.charged event whose notes.team_id refers to a non-existent team
// causes UpgradeTeamAllTiersWithSubscription to see 0 rows affected and return
// ErrTeamNotFound → the webhook maps it to 404 team_not_found (4xx so Razorpay
// does not retry). This is the rows-affected guard.
func TestBillingBlock_WebhookUnknownTeam_RowsAffectedZero(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	// A syntactically-valid UUID that is NOT in teams → 0 rows affected.
	bogusTeamID := uuid.NewString()
	subID := "sub_unknown_" + uuid.NewString()
	eventID := "evt_unknown_" + uuid.NewString()
	payload := makeSubscriptionChargedPayloadWithPlan(t, bogusTeamID, subID, cfg.RazorpayPlanIDPro)

	status, body := postSignedWebhook(t, app, payload, eventID)
	assert.Equal(t, http.StatusNotFound, status,
		"a signed charged event for an unknown team must 404 (rows-affected 0 → ErrTeamNotFound; 4xx = non-retryable)")
	assert.Equal(t, "team_not_found", body["error"],
		"the 404 envelope must carry the stable team_not_found code")

	db.Exec(`DELETE FROM razorpay_webhook_events WHERE event_id = $1`, eventID)
	db.Exec(`DELETE FROM audit_log WHERE metadata->>'event_id' = $1`, eventID)
}

// TestBillingBlock_CheckoutGracefulFailure_BillingNotConfigured — checkout
// graceful failure. With Razorpay credentials present but the requested tier's
// plan_id UNSET, /billing/checkout must return the documented 503
// billing_not_configured — never a 500/panic. The handler must reach the
// not-configured branch (not be short-circuited by a misconfig/already-on-tier
// guard), so we use a fresh free team + a rzp_test_* key with no plan_id.
func TestBillingBlock_CheckoutGracefulFailure_BillingNotConfigured(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	// Key + secret set, but RazorpayPlanIDPro deliberately UNSET → planID==""
	// → 503 billing_not_configured. Environment=production + rzp_test_ key so
	// the live-key-in-nonprod guard does not fire first.
	cfg := &config.Config{
		JWTSecret:         billingBlockJWTSecret,
		Environment:       "production",
		RazorpayKeyID:     "rzp_test_blockfixturekey",
		RazorpayKeySecret: "secret",
		// RazorpayPlanIDPro intentionally empty.
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		t.Fatal("CreateSubscription must NOT be called when the plan_id is unconfigured")
		return nil, nil
	}

	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	assert.Equal(t, http.StatusServiceUnavailable, code, "body=%v", body)
	assert.Equal(t, "billing_not_configured", body["error"],
		"an unconfigured plan_id must yield a graceful 503 billing_not_configured, not a 500/panic")
}

// TestBillingBlock_CheckoutGracefulFailure_LiveKeyInNonProd — the
// live-key-in-nonprod guard path. A LIVE Razorpay key on a non-production
// deployment must fast-fail with 503 billing_misconfigured BEFORE any
// subscription is minted — real money must never flow through a dev/staging
// deployment.
func TestBillingBlock_CheckoutGracefulFailure_LiveKeyInNonProd(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()

	cfg := &config.Config{
		JWTSecret:         billingBlockJWTSecret,
		Environment:       "development", // non-prod
		RazorpayKeyID:     "rzp_live_blockfixturekey",
		RazorpayKeySecret: "secret",
		RazorpayPlanIDPro: "plan_pro",
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		t.Fatal("CreateSubscription must NOT be called with a live key on a non-prod deployment")
		return nil, nil
	}

	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	assert.Equal(t, http.StatusServiceUnavailable, code, "body=%v", body)
	assert.Equal(t, "billing_misconfigured", body["error"],
		"a LIVE key on a non-prod deployment must 503 billing_misconfigured before minting a subscription")
}
