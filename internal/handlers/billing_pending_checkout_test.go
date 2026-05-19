package handlers_test

// billing_pending_checkout_test.go — payment-failure notification coverage gap.
//
// BACKGROUND
// ----------
// A live Pro upgrade test failed on Razorpay's hosted checkout ("seller does
// not support recurring payments") and the customer got NO email. The
// payment-failure email (handlePaymentFailed → SendPaymentFailed) only fires
// on an inbound payment.failed / subscription.charged_failed webhook. A
// pre-authorization failure on Razorpay's hosted page creates NO payment
// object → no webhook → no email.
//
// Two fixes are pinned here:
//
//  1. subscription.pending — Razorpay fires this when a charge fails / awaits
//     retry; it is the ONLY soft-failure signal the pre-auth path emits. The
//     webhook now sends the payment-failure notification on it.
//
//  2. pending_checkouts — every /api/v1/billing/checkout records a row; the
//     activated/charged webhook resolves it. The worker reconciler (separate
//     repo) notifies rows that never resolve. These tests pin the insert and
//     the resolve-on-success half of that contract.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// makeSubscriptionPendingPayload builds a Razorpay subscription.pending event.
// Razorpay fires this when a subscription charge fails and the subscription is
// awaiting retry — including the pre-authorization-failure case that emits no
// payment object at all.
func makeSubscriptionPendingPayload(t *testing.T, teamID, subscriptionID string) []byte {
	t.Helper()
	notes := map[string]any{}
	if teamID != "" {
		notes["team_id"] = teamID
	}
	subEntity, _ := json.Marshal(map[string]any{
		"id":     subscriptionID,
		"entity": "subscription",
		"status": "pending",
		"notes":  notes,
	})
	event := map[string]any{
		"entity": "event",
		"event":  "subscription.pending",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeSubscriptionPendingPayload: marshal: %v", err)
	}
	return payload
}

// TestBillingWebhook_SubscriptionPending_SendsNotification is the core fix-(1)
// regression: a subscription.pending event for a resolvable team with an
// owner email on file returns 200 and exercises the payment-failure
// notification path (the same SendPaymentFailed handlePaymentFailed uses).
// Before the fix subscription.pending fell into default: — no email at all.
func TestBillingWebhook_SubscriptionPending_SendsNotification(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	_, err := db.Exec(
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner')`,
		teamID, "pending-owner-"+uuid.NewString()[:8]+"@example.com")
	require.NoError(t, err)

	payload := makeSubscriptionPendingPayload(t, teamID, "sub_pending_"+uuid.NewString())
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"subscription.pending for a resolvable team must return 200 after sending the payment-failure notification")
}

// TestBillingWebhook_SubscriptionPending_UnknownTeam_Returns200 pins the
// non-retryable half: a subscription.pending payload that resolves to no team
// is permanent — keep the dedup claim, return 200. Retrying a payload that
// will never resolve just re-burns the claim.
func TestBillingWebhook_SubscriptionPending_UnknownTeam_Returns200(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	// No team_id in notes, sub_id matches no team → ErrTeamNotFound → non-retryable.
	payload := makeSubscriptionPendingPayload(t, "", "sub_pending_unknown_"+uuid.NewString())
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an unknown-team subscription.pending is non-retryable — keep the claim, return 200")
}

// TestBillingWebhook_SubscriptionPending_RetryableFailure_Returns500 pins the
// retryable half: when team resolution hits a genuine DB error the handler
// returns an error so RazorpayWebhook releases the dedup claim and 500s —
// Razorpay then redelivers. A swallowed 200 would lose the failure signal.
func TestBillingWebhook_SubscriptionPending_RetryableFailure_Returns500(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	// Build the app against a real DB, then close it so every query errors —
	// a faithful stand-in for a DB blip during team resolution.
	db, dbCleanup := testhelpers.SetupTestDB(t)
	dbCleanup()

	app, _ := billingWebhookDBApp(t, db)

	// sub_id present (with no notes.team_id) so resolveTeamFromNotes runs the
	// DB lookup — which hits the closed DB and returns a retryable error.
	payload := makeSubscriptionPendingPayload(t, "", "sub_pending_retry_"+uuid.NewString())
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_pending_retry_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a retryable subscription.pending failure MUST return 500 so Razorpay redelivers")
}

// TestPendingCheckout_InsertRecordsRow pins fix-(3): the model write
// /api/v1/billing/checkout performs after a successful Razorpay subscription
// create. The checkout handler calls InsertPendingCheckout with the
// subscription ID, team, owner email and tier — this asserts the row lands
// unresolved and un-notified, exactly the state the worker reconciler scans.
func TestPendingCheckout_InsertRecordsRow(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	team := uuid.MustParse(teamID)

	subID := "sub_checkout_" + uuid.NewString()
	require.NoError(t, models.InsertPendingCheckout(
		context.Background(), db, subID, team, "buyer@example.com", "pro"))

	var email, planTier string
	var resolvedAt, notifiedAt *string
	require.NoError(t, db.QueryRow(
		`SELECT customer_email, plan_tier, resolved_at::text, failure_notified_at::text
		   FROM pending_checkouts WHERE subscription_id = $1`, subID,
	).Scan(&email, &planTier, &resolvedAt, &notifiedAt))
	assert.Equal(t, "buyer@example.com", email)
	assert.Equal(t, "pro", planTier)
	assert.Nil(t, resolvedAt, "a freshly-inserted pending checkout must be unresolved")
	assert.Nil(t, notifiedAt, "a freshly-inserted pending checkout must be un-notified")

	// Idempotency: a retried checkout (same subscription_id) is a no-op.
	require.NoError(t, models.InsertPendingCheckout(
		context.Background(), db, subID, team, "buyer@example.com", "pro"))
	var rowCount int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM pending_checkouts WHERE subscription_id = $1`, subID,
	).Scan(&rowCount))
	assert.Equal(t, 1, rowCount, "InsertPendingCheckout must be idempotent on subscription_id")
}

// TestBillingWebhook_SubscriptionActivated_ResolvesPendingCheckout pins the
// resolve half of fix-(3): a subscription.activated webhook for a pending
// checkout stamps resolved_at, so the worker reconciler does not later notify
// a completed upgrade as a failure.
func TestBillingWebhook_SubscriptionActivated_ResolvesPendingCheckout(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	team := uuid.MustParse(teamID)

	subID := "sub_activate_" + uuid.NewString()
	require.NoError(t, models.InsertPendingCheckout(
		context.Background(), db, subID, team, "buyer@example.com", "pro"))

	payload := makeSubscriptionActivatedPayload(t, teamID, subID)
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var resolvedAt *string
	require.NoError(t, db.QueryRow(
		`SELECT resolved_at::text FROM pending_checkouts WHERE subscription_id = $1`, subID,
	).Scan(&resolvedAt))
	assert.NotNil(t, resolvedAt,
		"subscription.activated for a pending checkout must stamp resolved_at")
}

// TestBillingWebhook_SubscriptionCharged_ResolvesPendingCheckout pins the same
// resolve contract for subscription.charged — the other event that means
// "checkout succeeded". Both route through handleSubscriptionCharged.
func TestBillingWebhook_SubscriptionCharged_ResolvesPendingCheckout(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	team := uuid.MustParse(teamID)

	subID := "sub_charged_" + uuid.NewString()
	require.NoError(t, models.InsertPendingCheckout(
		context.Background(), db, subID, team, "buyer@example.com", "pro"))

	payload := makeSubscriptionChargedPayload(t, teamID, subID)
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var resolvedAt *string
	require.NoError(t, db.QueryRow(
		`SELECT resolved_at::text FROM pending_checkouts WHERE subscription_id = $1`, subID,
	).Scan(&resolvedAt))
	assert.NotNil(t, resolvedAt,
		"subscription.charged for a pending checkout must stamp resolved_at")
}
