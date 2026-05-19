package handlers_test

// billing_trust_test.go — regression coverage for the BILLING-TRUST-AUDIT
// 2026-05-19 findings F2, F3, F4, F8, F12. Each test FAILS without the
// matching fix and PASSES with it.
//
//	F2  — handleSubscriptionCharged must distinguish a transient DB error
//	      (→ 500, Razorpay retries) from a genuinely unresolvable team
//	      (→ 200, no retry). Pre-fix it returned 200 for both, permanently
//	      losing a real charge on a DB blip.
//	F3  — a subscription.charged for a plan tier not in plans.yaml must be
//	      LOUD: a billing.charge_undeliverable audit row, not a silent 200.
//	F4  — a successful charge must send the customer a payment receipt
//	      email (SendPaymentSucceeded).
//	F8  — an undeliverable charge (unresolvable team OR unknown tier) must
//	      write a billing.charge_undeliverable audit row.
//	F12 — a subscription.completed on a HEALTHY paying subscription must
//	      NOT downgrade the team — the pre-fix code punished a loyal
//	      12-month paying customer.
//
// DB-backed tests run against a real test Postgres (skipped cleanly when
// TEST_DATABASE_URL is unset, matching the rest of the suite). The F2
// transient-error test deliberately closes the DB so every query errors —
// the same faithful stand-in used by billing_webhook_failure_signal_test.go.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// auditKindChargeUndeliverable is the audit_log.kind the F8 make-good path
// writes. Pinned here as a literal so a rename of the models constant breaks
// this test (the test is the contract guard for the kind string).
const auditKindChargeUndeliverable = "billing.charge_undeliverable"

// billingTrustURLRewriter is a tiny http.RoundTripper that swaps the
// scheme+host of every outbound request with a test server's, so the F4
// receipt test can point the Brevo email backend at httptest.Server without
// touching the production endpoint constant. (A sibling exists in
// email_test.go but lives in a different test package.)
type billingTrustURLRewriter struct {
	base  string
	inner http.RoundTripper
}

func (u *billingTrustURLRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if idx := strings.Index(u.base, "://"); idx > 0 {
		req.URL.Scheme = u.base[:idx]
		req.URL.Host = u.base[idx+3:]
	}
	return u.inner.RoundTrip(req)
}

// makeChargedPayloadFull builds a subscription.charged event with full
// control: optional team_id in notes, an explicit plan_id, an optional
// paid_count, and an optional payload.payment entity (amount + currency) so
// the F4 receipt-amount extraction is exercised. Pass paidCount < 0 to omit
// the field entirely; payAmountMinor <= 0 omits the payment entity.
func makeChargedPayloadFull(t *testing.T, teamID, subscriptionID, planID string, paidCount int, payAmountMinor int64, currency string) []byte {
	t.Helper()
	notes := map[string]any{}
	if teamID != "" {
		notes["team_id"] = teamID
	}
	subFields := map[string]any{
		"id":      subscriptionID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  "active",
		"notes":   notes,
	}
	if paidCount >= 0 {
		subFields["paid_count"] = paidCount
	}
	subEntity, _ := json.Marshal(subFields)

	payload := map[string]any{
		"subscription": map[string]any{
			"entity": json.RawMessage(subEntity),
		},
	}
	if payAmountMinor > 0 {
		payEntity, _ := json.Marshal(map[string]any{
			"id":       "pay_ok_" + uuid.NewString(),
			"entity":   "payment",
			"amount":   payAmountMinor,
			"currency": currency,
		})
		payload["payment"] = map[string]any{
			"entity": json.RawMessage(payEntity),
		}
	}
	event := map[string]any{
		"entity":  "event",
		"event":   "subscription.charged",
		"payload": payload,
	}
	out, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeChargedPayloadFull: %v", err)
	}
	return out
}

// ── F2 ──────────────────────────────────────────────────────────────────────

// TestBillingWebhook_ChargedTransientDBError_Returns500 is the F2 P0
// regression. A subscription.charged whose team must be resolved by the
// subscription-id DB lookup hits a closed DB → a real (transient) DB error,
// NOT ErrTeamNotFound. The handler must classify that as retryable and return
// 500 so Razorpay redelivers. Pre-fix it returned 200 and the charge was lost.
func TestBillingWebhook_ChargedTransientDBError_Returns500(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}

	// Build against a real DB, then close it so every query errors.
	db, dbCleanup := testhelpers.SetupTestDB(t)
	dbCleanup()

	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDPro:     "plan_test_pro",
	}
	billing := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	// No team_id in notes → resolveTeamFromNotes falls back to a DB lookup by
	// subscription_id. Against the closed DB that lookup returns a real DB
	// error (wrapped, NOT ErrTeamNotFound) → retryable → 500.
	payload := makeChargedPayloadFull(t, "", "sub_transient_"+uuid.NewString(), "plan_test_pro", -1, 0, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_transient_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a transient DB error during charged team-resolve MUST return 500 so Razorpay retries — not a swallowed 200")
}

// TestBillingWebhook_ChargedUnresolvableTeam_Returns200WithAudit is the other
// half of F2 + the F8 make-good path: a charged event with no team_id and no
// subscription_id can never resolve → ErrTeamUnresolvable → non-retryable. The
// webhook returns 200 (retrying is pointless) AND writes a
// billing.charge_undeliverable audit row so an operator can reconcile it.
func TestBillingWebhook_ChargedUnresolvableTeam_Returns200WithAudit(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	// app + assertions must share ONE database, so build the app over an
	// explicit db handle rather than billingTestAppWithRealDB (which owns its
	// own db internally and would write the audit row where we cannot see it).
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	// Empty team_id AND empty subscription_id → ErrTeamUnresolvable.
	payload := makeChargedPayloadFull(t, "", "", "plan_test_pro", -1, 0, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_unresolvable_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an unresolvable-team charge is non-retryable — must return 200, not 500")

	// A billing.charge_undeliverable audit row must have been written with a
	// NULL team_id (the team was unresolvable) and reason team_unresolvable.
	var cnt int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id IS NULL AND kind = $1
		   AND metadata->>'reason' = 'team_unresolvable'`,
		auditKindChargeUndeliverable).Scan(&cnt))
	assert.GreaterOrEqual(t, cnt, 1,
		"an unresolvable charge must write a billing.charge_undeliverable audit row (F8)")
}

// ── F3 + F8 ─────────────────────────────────────────────────────────────────

// TestBillingWebhook_ChargedUnrecognisedPlanID_WritesUndeliverableAudit is the
// F3 + F8 regression. A subscription.charged whose plan_id matches NO
// configured RAZORPAY_PLAN_ID_* value (an env-var typo, or a Razorpay-dashboard
// plan that was never wired) means the platform does not actually know what
// tier the customer paid for. Pre-fix this was silently mapped to the fallback
// tier and the charge produced no operator-visible signal at all. The fix:
// the safe fallback tier is still granted (so the customer is not stranded on
// free), but a billing.charge_undeliverable audit row with reason
// "unknown_tier" is written so an operator can verify/refund. The webhook
// returns 200 — Razorpay retrying cannot fix an env-var typo.
func TestBillingWebhook_ChargedUnrecognisedPlanID_WritesUndeliverableAudit(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// plan_id "plan_typo_not_configured" matches none of billingWebhookDBApp's
	// configured RazorpayPlanID* values → planIDRecognised == false → F3.
	payload := makeChargedPayloadFull(t, teamID, "sub_badplan_"+uuid.NewString(),
		"plan_typo_not_configured", 1, 0, "")
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an unrecognised-plan charge must return 200 — an env-var fix, not a Razorpay retry, is needed")

	// The make-good audit row MUST have been written with reason unknown_tier.
	var cnt int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = $2
		   AND metadata->>'reason' = 'unknown_tier'`,
		teamID, auditKindChargeUndeliverable).Scan(&cnt))
	assert.GreaterOrEqual(t, cnt, 1,
		"an unrecognised-plan charge must write a billing.charge_undeliverable audit row (F3/F8) — not a silent 200")
}

// TestBillingWebhook_ChargedKnownPlanID_NoUndeliverableAudit is the negative
// control for F3: a charge for a properly configured plan_id must NOT write a
// charge_undeliverable row — the make-good audit is reason-gated, not emitted
// on every charge.
func TestBillingWebhook_ChargedKnownPlanID_NoUndeliverableAudit(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := makeChargedPayloadFull(t, teamID, "sub_ok_"+uuid.NewString(),
		cfg.RazorpayPlanIDPro, 1, 0, "")
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var cnt int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = $2`,
		teamID, auditKindChargeUndeliverable).Scan(&cnt))
	assert.Equal(t, 0, cnt,
		"a charge for a recognised plan_id must NOT write a charge_undeliverable row")
}

// ── F4 ──────────────────────────────────────────────────────────────────────

// TestBillingWebhook_ChargedSuccess_SendsReceiptEmail is the F4 regression: a
// successful subscription.charged must send the customer a payment receipt.
// We wire the handler's email client to a fake Brevo server and assert a
// receipt email was POSTed carrying the plan + amount.
func TestBillingWebhook_ChargedSuccess_SendsReceiptEmail(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Fake Brevo server captures every outbound email.
	var captured []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		captured = append(captured, body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	emailClient := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test",
		HTTPClient:  &http.Client{Transport: &billingTrustURLRewriter{base: srv.URL, inner: http.DefaultTransport}},
	})

	cfg := &config.Config{
		JWTSecret:             testhelpers.TestJWTSecret,
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDHobby:   "plan_test_hobby",
		RazorpayPlanIDPro:     "plan_test_pro",
	}
	billing := handlers.NewBillingHandler(db, cfg, emailClient)
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	// Seed an owner so GetUserByTeamID resolves a recipient address.
	_, err := db.Exec(`
		INSERT INTO users (team_id, email, role, email_verified)
		VALUES ($1::uuid, $2, 'owner', true)`,
		teamID, "receipt-owner@example.com")
	require.NoError(t, err)

	// subscription.charged for the pro plan, carrying a real payment entity
	// (₹4900.00 = 490000 paise) so the receipt amount is exercised.
	payload := makeChargedPayloadFull(t, teamID, "sub_receipt_"+uuid.NewString(),
		cfg.RazorpayPlanIDPro, 1, 490000, "INR")
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Exactly one receipt email must have been sent to the owner.
	var receipt map[string]any
	for _, body := range captured {
		subj, _ := body["subject"].(string)
		if strings.Contains(strings.ToLower(subj), "payment received") {
			receipt = body
			break
		}
	}
	require.NotNil(t, receipt, "a successful charge must send a payment receipt email (F4)")

	toList, _ := receipt["to"].([]any)
	require.Len(t, toList, 1)
	recip, _ := toList[0].(map[string]any)
	assert.Equal(t, "receipt-owner@example.com", recip["email"])

	txt, _ := receipt["textContent"].(string)
	assert.Contains(t, txt, "₹4900.00", "receipt must show the charged amount")
}

// ── F12 ─────────────────────────────────────────────────────────────────────

// TestBillingWebhook_SubscriptionCompleted_HealthyPayingTeam_NotDowngraded is
// the F12 regression. A subscription.completed whose subscription has a
// healthy paid_count (the loyal 12-month customer) must NOT be downgraded.
// Pre-fix this routed to handleSubscriptionCancelled and dropped the team to
// hobby — punishing a customer who paid every month.
func TestBillingWebhook_SubscriptionCompleted_HealthyPayingTeam_NotDowngraded(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// paid_count = 12: a year of healthy monthly payments. The legacy
	// total_count:12 subscription auto-completes here.
	payload := makeSubscriptionLifecyclePayload(t, "subscription.completed", teamID, "sub_"+uuid.NewString(), 12)
	postLifecycleWebhook(t, app, payload)

	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "pro", planTier,
		"a completed subscription with healthy payments must keep the customer on their plan (F12) — not downgrade to hobby")

	// And no cancellation audit row — the customer was not canceled.
	var cancelAudits int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'subscription.canceled'`,
		teamID).Scan(&cancelAudits))
	assert.Equal(t, 0, cancelAudits,
		"a healthy completion must NOT emit a subscription.canceled audit/email")
}

// TestBillingWebhook_SubscriptionCompleted_NeverPaid_StillDowngrades pins the
// other half of F12: a completion with paid_count == 0 (the subscription ended
// without a single successful charge) is a genuine end-of-relationship and
// must still downgrade — the F12 fix protects PAYING customers only.
func TestBillingWebhook_SubscriptionCompleted_NeverPaid_StillDowngrades(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// paid_count = 0 → never charged → genuine downgrade.
	payload := makeSubscriptionLifecyclePayload(t, "subscription.completed", teamID, "sub_"+uuid.NewString(), 0)
	postLifecycleWebhook(t, app, payload)

	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "free", planTier,
		"a completion with zero paid invoices must still downgrade (paid_count==0 → free floor)")
}
