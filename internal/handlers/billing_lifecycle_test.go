package handlers_test

// billing_lifecycle_test.go — P1-F coverage (bug hunt 2026-05-17 round 2).
//
// RazorpayWebhook previously handled only activated / charged / cancelled /
// charged_failed / payment.failed and silently dropped the remaining
// subscription lifecycle events. That left a halted/completed subscription on
// paid-tier limits, and a paused subscription with no grace period, until the
// 15-minute reconciler caught up.
//
// This file drives signed webhooks for the four newly-handled events:
//   - subscription.halted     → downgrade (terminal, retries exhausted)
//   - subscription.completed  → downgrade (term ended)
//   - subscription.paused     → open grace period
//   - subscription.resumed    → recover the grace period
//
// Real Postgres + signed payloads, mirroring billing_dunning_test.go.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// makeSubscriptionLifecyclePayload builds a Razorpay subscription lifecycle
// webhook payload for the given event name. teamID is stamped into
// notes.team_id so resolveTeamFromNotes resolves the team directly.
// paidCount is encoded as the subscription's paid_count so the downgrade
// policy (free vs hobby floor) can be exercised.
func makeSubscriptionLifecyclePayload(t *testing.T, eventName, teamID, subscriptionID string, paidCount int) []byte {
	t.Helper()
	subEntity, _ := json.Marshal(map[string]any{
		"id":         subscriptionID,
		"entity":     "subscription",
		"plan_id":    "plan_test_pro",
		"status":     "active",
		"paid_count": paidCount,
		"notes":      map[string]any{"team_id": teamID},
	})
	event := map[string]any{
		"entity": "event",
		"event":  eventName,
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeSubscriptionLifecyclePayload: %v", err)
	}
	return payload
}

// postLifecycleWebhook signs and posts a lifecycle payload, asserting 200.
func postLifecycleWebhook(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, payload []byte) {
	t.Helper()
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestBillingWebhook_SubscriptionHalted_Downgrades verifies a halted
// subscription (all charge retries exhausted) downgrades the team — it must
// not keep paid-tier limits waiting on the reconciler.
func TestBillingWebhook_SubscriptionHalted_Downgrades(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// paid_count > 0 → hobby floor (the team paid at least once).
	payload := makeSubscriptionLifecyclePayload(t, "subscription.halted", teamID, "sub_"+uuid.NewString(), 3)
	postLifecycleWebhook(t, app, payload)

	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "hobby", planTier, "halted subscription must downgrade the team")
}

// TestBillingWebhook_SubscriptionCompleted_Downgrades verifies a completed
// subscription (agreed term ended) downgrades the team.
func TestBillingWebhook_SubscriptionCompleted_Downgrades(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := makeSubscriptionLifecyclePayload(t, "subscription.completed", teamID, "sub_"+uuid.NewString(), 12)
	postLifecycleWebhook(t, app, payload)

	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "hobby", planTier, "completed subscription must downgrade the team")
}

// TestBillingWebhook_SubscriptionPaused_OpensGrace verifies a paused
// subscription opens an active grace period and leaves the tier intact.
func TestBillingWebhook_SubscriptionPaused_OpensGrace(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_" + uuid.NewString()
	postLifecycleWebhook(t, app, makeSubscriptionLifecyclePayload(t, "subscription.paused", teamID, subID, 4))

	var status, subscriptionID string
	require.NoError(t, db.QueryRow(`
		SELECT status, subscription_id FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamID).Scan(&status, &subscriptionID))
	assert.Equal(t, "active", status, "paused subscription must open a grace period")
	assert.Equal(t, subID, subscriptionID)

	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "pro", planTier, "pause must not downgrade immediately — grace covers the window")
}

// TestBillingWebhook_SubscriptionResumed_RecoversGrace verifies that resuming
// a previously-paused subscription flips its active grace row to 'recovered',
// stopping the dunning clock.
func TestBillingWebhook_SubscriptionResumed_RecoversGrace(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_" + uuid.NewString()
	// Pause → opens grace.
	postLifecycleWebhook(t, app, makeSubscriptionLifecyclePayload(t, "subscription.paused", teamID, subID, 4))
	// Resume → recovers grace.
	postLifecycleWebhook(t, app, makeSubscriptionLifecyclePayload(t, "subscription.resumed", teamID, subID, 4))

	var status string
	require.NoError(t, db.QueryRow(`
		SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid ORDER BY started_at DESC LIMIT 1`,
		teamID).Scan(&status))
	assert.Equal(t, "recovered", status, "resume must recover the active grace period")
}

// TestBillingWebhook_SubscriptionResumed_NoGraceIsNoop verifies that a resume
// with no prior pause is a clean no-op (returns 200, no panic, no grace row).
func TestBillingWebhook_SubscriptionResumed_NoGraceIsNoop(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	postLifecycleWebhook(t, app, makeSubscriptionLifecyclePayload(t, "subscription.resumed", teamID, "sub_"+uuid.NewString(), 4))

	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID).Scan(&n))
	assert.Equal(t, 0, n, "resume with no prior pause must not create a grace row")
}
