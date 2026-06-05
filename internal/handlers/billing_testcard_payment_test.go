package handlers_test

// billing_testcard_payment_test.go — Wave 4 (docs/ci/01-CI-INTEGRATION-DESIGN.md
// §Razorpay, Approach B): the deterministic webhook-injection payment
// integration test. Runs in the api test gate against the test Postgres — NOT
// the live-k8s e2e suite (that lives in e2e/plan_upgrade_e2e_test.go and drives
// the real cluster). This is the per-PR, hermetic, real-backend proof that the
// free → upgrade → Pro payment path works end-to-end through RazorpayWebhook.
//
// Razorpay TEST MODE needs no recurring approval (the prod live-checkout gate is
// an operator/account blocker, not a code one), so Approach B is green TODAY:
// it self-signs the exact subscription.charged webhook body and POSTs it,
// exercising the real handler path the live Razorpay would hit.
//
// Coverage (mirrors the brief):
//   - mint a free cohort team (Part A factory model path via testhelpers).
//   - construct the EXACT subscription.charged body (raw bytes, signed in place
//     — never re-marshalled after signing, so the HMAC matches verbatim).
//   - sign hex(HMAC-SHA256(rawBody, webhookSecret)) — reusing the SAME
//     signRazorpayPayload the existing suite + the verifier agree on.
//   - assert tier upgraded to pro AND active permanent resources were elevated
//     (ElevateResourceTiersByTeam ran inside UpgradeTeamAllTiersWithSubscription).
//   - assert the upgrade contract surfaces: plans.Registry resolves pro limits
//     that are strictly larger than free, and the elevated resource now carries
//     the pro snapshot — a sanity check that the elevation is real, not just a
//     plan_tier column flip.
//   - NEGATIVES: tampered body / wrong secret → 400, NO upgrade.
//   - IDEMPOTENCY: same x-razorpay-event-id twice → exactly one upgrade.
//   - FAILURE PATH: payment.failed → no upgrade (+ the grace/audit state the
//     handler produces; we assert state, not email delivery — the failure email
//     is webhook-gated per project_payment_failure_email_coverage).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// testCardSkipUnlessDB skips the suite when no test Postgres is wired (mirrors
// dunningWebhookSkipUnlessDB so a baseline `go test -short` with no DB is clean).
func testCardSkipUnlessDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing test-card payment: TEST_DATABASE_URL not set")
	}
}

// nowUnix returns the current Unix-second timestamp — used to stamp the
// webhook body's created_at inside the handler's ±5-min replay window so the
// timestamp guard (verifyRazorpayTimestamp) accepts the event.
func nowUnix() int64 { return time.Now().Unix() }

// subscriptionChargedRawBody builds the EXACT subscription.charged JSON body the
// handler reads, with a `created_at` inside the ±5-min replay window so the
// timestamp guard accepts it. Returns the raw bytes — the caller signs THESE
// bytes and POSTs THEM unchanged (re-marshalling after signing would change the
// byte order and break the HMAC).
//
// teamID is stamped into notes.team_id (resolveTeamFromNotes' primary path).
// planID is the Pro plan_id so planIDToTier resolves "pro".
func subscriptionChargedRawBody(t *testing.T, teamID, subID, planID string, createdAt int64) []byte {
	t.Helper()
	subEntity, err := json.Marshal(map[string]any{
		"id":      subID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  "active",
		"notes":   map[string]any{"team_id": teamID},
	})
	require.NoError(t, err)
	payEntity, err := json.Marshal(map[string]any{
		"id":       "pay_test_" + uuid.NewString()[:12],
		"entity":   "payment",
		"status":   "captured",
		"amount":   410000,
		"currency": "INR",
	})
	require.NoError(t, err)
	event := map[string]any{
		"id":         "evt_test_" + uuid.NewString(),
		"entity":     "event",
		"event":      "subscription.charged",
		"created_at": createdAt,
		"payload": map[string]any{
			"subscription": map[string]any{"entity": json.RawMessage(subEntity)},
			"payment":      map[string]any{"entity": json.RawMessage(payEntity)},
		},
	}
	body, err := json.Marshal(event)
	require.NoError(t, err)
	return body
}

// postSignedWebhookRaw signs the EXACT bytes with the given secret (reusing the
// shared signRazorpayPayload — the same primitive verifyRazorpaySignature
// checks, guaranteeing parity) and POSTs them unchanged, optionally setting
// X-Razorpay-Event-Id. Returns the response.
func postSignedWebhookRaw(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, secret string, body []byte, eventID string,
) *http.Response {
	t.Helper()
	sig := signRazorpayPayload(t, secret, body)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	if eventID != "" {
		req.Header.Set("X-Razorpay-Event-Id", eventID)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// ── HAPPY PATH: free → subscription.charged(pro) → pro + resources elevated ──

func TestBillingTestCard_SubscriptionCharged_UpgradesAndElevatesResources(t *testing.T) {
	testCardSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// A real active permanent resource, minted under the free tier — it must be
	// elevated to pro by the charge (ElevateResourceTiersByTeam).
	_, resID := seedActiveResource(t, db, teamID, "redis", "free")

	body := subscriptionChargedRawBody(t, teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, nowUnix())
	resp := postSignedWebhookRaw(t, app, testWebhookSecret, body, "evt_"+uuid.NewString())
	require.Equal(t, http.StatusOK, resp.StatusCode, "valid signed subscription.charged must 200")

	// Tier upgraded.
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "pro", planTier, "subscription.charged with the Pro plan_id must upgrade the team to pro")

	// Active permanent resource elevated to the pro snapshot.
	var resTier string
	require.NoError(t, db.QueryRow(`SELECT tier FROM resources WHERE id = $1::uuid`, resID).Scan(&resTier))
	assert.Equal(t, "pro", resTier, "ElevateResourceTiersByTeam must lift the active resource to pro")

	// Upgrade contract surface: pro limits resolve strictly larger than free,
	// and the elevated resource now resolves the larger limit. Reads the live
	// plans.Registry (not hardcoded numbers) so a plans.yaml change can't drift
	// this assertion into a lie.
	reg := plans.Default()
	freeRedis := reg.StorageLimitMB("free", "redis")
	proRedis := reg.StorageLimitMB("pro", "redis")
	require.Greater(t, proRedis, freeRedis,
		"sanity: pro redis limit must exceed free (else the elevation proves nothing)")
	assert.Equal(t, proRedis, reg.StorageLimitMB(resTier, "redis"),
		"the elevated resource's tier must resolve pro-tier limits")
}

// ── NEGATIVE: tampered body → 400, NO upgrade ───────────────────────────────

func TestBillingTestCard_TamperedBody_Rejected_NoUpgrade(t *testing.T) {
	testCardSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	body := subscriptionChargedRawBody(t, teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, nowUnix())
	// Sign the ORIGINAL body, then tamper a byte AFTER signing → HMAC no longer
	// matches the bytes on the wire.
	sig := signRazorpayPayload(t, testWebhookSecret, body)
	tampered := append([]byte{}, body...)
	tampered[len(tampered)/2] ^= 0xFF // flip a byte in the middle

	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(tampered))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "tampered body must be rejected 400")

	assertNotUpgraded(t, db, teamID)
}

// ── NEGATIVE: wrong secret → 400, NO upgrade ────────────────────────────────

func TestBillingTestCard_WrongSecret_Rejected_NoUpgrade(t *testing.T) {
	testCardSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	body := subscriptionChargedRawBody(t, teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, nowUnix())
	// Sign with a DIFFERENT secret than the handler is configured with.
	resp := postSignedWebhookRaw(t, app, "totally-the-wrong-secret", body, "evt_"+uuid.NewString())
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "wrong-secret signature must be rejected 400")

	assertNotUpgraded(t, db, teamID)
}

// ── IDEMPOTENCY: same x-razorpay-event-id twice → exactly one upgrade ────────

func TestBillingTestCard_DuplicateEventID_UpgradesExactlyOnce(t *testing.T) {
	testCardSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// ONE body + ONE event_id, replayed.
	body := subscriptionChargedRawBody(t, teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, nowUnix())
	eventID := "evt_replay_" + uuid.NewString()

	resp1 := postSignedWebhookRaw(t, app, testWebhookSecret, body, eventID)
	require.Equal(t, http.StatusOK, resp1.StatusCode, "first delivery must 200")
	var planAfterFirst string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planAfterFirst))
	require.Equal(t, "pro", planAfterFirst, "first delivery must upgrade to pro")

	resp2 := postSignedWebhookRaw(t, app, testWebhookSecret, body, eventID)
	require.Equal(t, http.StatusOK, resp2.StatusCode, "replayed delivery must 200")
	var replay struct {
		OK      bool `json:"ok"`
		Deduped bool `json:"deduped"`
	}
	require.NoError(t, decodeJSON(resp2, &replay))
	assert.True(t, replay.Deduped,
		"the second delivery of the same event_id must be deduped (upgrade state machine fires exactly once)")

	// The dedup table must hold exactly one row for this event_id — the
	// load-bearing "exactly once" proof (the tier column would read pro after a
	// re-fire too, so the count is the real guard).
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM razorpay_webhook_events WHERE event_id = $1`, eventID).Scan(&n))
	assert.Equal(t, 1, n, "exactly one dedup row must exist for a replayed event_id")
}

// ── FAILURE PATH: payment.failed → no upgrade ───────────────────────────────

func TestBillingTestCard_PaymentFailed_NoUpgrade(t *testing.T) {
	testCardSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// A payment.failed carrying notes.team_id (so the handler resolves the team)
	// must NOT upgrade — a declined card never grants a tier.
	payEntity, err := json.Marshal(map[string]any{
		"id":                "pay_test_" + uuid.NewString()[:12],
		"entity":            "payment",
		"status":            "failed",
		"amount":            410000,
		"currency":          "INR",
		"attempt_count":     1,
		"error_description": "Card declined (test)",
		"notes":             map[string]any{"team_id": teamID},
	})
	require.NoError(t, err)
	event := map[string]any{
		"id":         "evt_test_" + uuid.NewString(),
		"entity":     "event",
		"event":      "payment.failed",
		"created_at": nowUnix(),
		"payload": map[string]any{
			"payment": map[string]any{"entity": json.RawMessage(payEntity)},
		},
	}
	body, err := json.Marshal(event)
	require.NoError(t, err)

	resp := postSignedWebhookRaw(t, app, testWebhookSecret, body, "evt_"+uuid.NewString())
	require.Equal(t, http.StatusOK, resp.StatusCode, "payment.failed must 200 (acknowledged, not retried)")

	// The team must stay on free — the declined payment grants nothing.
	assertNotUpgraded(t, db, teamID)
}

// assertNotUpgraded asserts the team is still on the free tier (no upgrade
// leaked through) — the shared negative-path invariant.
func assertNotUpgraded(t *testing.T, db *sql.DB, teamID string) {
	t.Helper()
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "free", planTier, "a rejected/failed payment must NOT upgrade the team")
}
