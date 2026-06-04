package handlers_test

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// Stale-sub downgrade guard (MONEY-SENSITIVE, 2026-06-04).
//
// A subscription.cancelled/halted/deauthenticated webhook carries
// notes.team_id verbatim from WHATEVER subscription fired it — including a
// SUPERSEDED one. After a hobby→pro plan change the old hobby subscription
// stays alive in Razorpay; its eventual cancellation must NOT downgrade the
// team that is now actively paying on a different live Pro subscription.
//
// These tests pin three behaviours exercised through the real webhook handler
// path (signature verify → dispatch → handleSubscriptionCancelled):
//   (a) a cancel for the team's LIVE subscription still downgrades.
//   (b) a cancel for a STALE/non-matching subscription id is IGNORED (no
//       UpdatePlanTier, a billing.charge_undeliverable audit row IS emitted).
//   (c) an empty live subscription id falls through to historical behaviour
//       (the team is downgraded — we cannot prove the event is stale).

// TestBillingWebhook_SubscriptionCancelled_LiveSub_StillDowngrades verifies
// behaviour (a): when the cancelled webhook's subscription_id MATCHES the
// team's stored live subscription, the historical downgrade still happens.
func TestBillingWebhook_SubscriptionCancelled_LiveSub_StillDowngrades(t *testing.T) {
	db, cleanDB := billingStateNeedsDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	liveSub := "sub_live_" + uuid.NewString()
	_, err := db.Exec(`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, liveSub, teamID)
	require.NoError(t, err)

	// Webhook fires for the SAME (live) subscription → downgrade proceeds.
	payload := makeSubscriptionCancelledPayload(t, teamID, liveSub)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Tier dropped to hobby (paid_count omitted → courtesy floor).
	var newTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&newTier))
	assert.Equal(t, "hobby", newTier, "cancel for the LIVE sub must downgrade")

	// No stale-skip audit row — this was a legitimate cancellation.
	var staleCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid
		   AND kind = 'billing.charge_undeliverable'
		   AND metadata->>'reason' = 'stale_subscription_cancel'`, teamID).Scan(&staleCount))
	assert.Equal(t, 0, staleCount, "live-sub cancel must NOT emit a stale-skip audit row")
}

// TestBillingWebhook_SubscriptionCancelled_StaleSub_IsIgnored verifies
// behaviour (b): a cancelled webhook whose subscription_id does NOT match the
// team's stored live subscription is treated as a superseded event — the tier
// is KEPT and a billing.charge_undeliverable (reason=stale_subscription_cancel)
// audit row is emitted for operator reconciliation.
func TestBillingWebhook_SubscriptionCancelled_StaleSub_IsIgnored(t *testing.T) {
	db, cleanDB := billingStateNeedsDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	liveSub := "sub_live_pro_" + uuid.NewString()
	_, err := db.Exec(`UPDATE teams SET stripe_customer_id = $1 WHERE id = $2::uuid`, liveSub, teamID)
	require.NoError(t, err)

	// Webhook fires for a DIFFERENT (superseded hobby) subscription.
	staleSub := "sub_stale_hobby_" + uuid.NewString()
	payload := makeSubscriptionCancelledPayload(t, teamID, staleSub)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Non-retryable skip keeps the 200 — Razorpay must not redeliver.
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Tier UNCHANGED — the actively-paying Pro customer must not be downgraded.
	var newTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&newTier))
	assert.Equal(t, "pro", newTier, "stale-sub cancel must NOT downgrade a live paying customer")

	// A stale-skip audit row IS emitted for operator reconciliation.
	var staleCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid
		   AND kind = 'billing.charge_undeliverable'
		   AND metadata->>'reason' = 'stale_subscription_cancel'`, teamID).Scan(&staleCount))
	assert.Equal(t, 1, staleCount, "stale-sub cancel must emit exactly one stale-skip audit row")

	// No subscription.canceled row — the cancellation email must NOT fire.
	var canceledCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'subscription.canceled'`, teamID).Scan(&canceledCount))
	assert.Equal(t, 0, canceledCount, "stale-sub cancel must NOT emit a customer cancellation row")
}

// TestBillingWebhook_SubscriptionCancelled_EmptyLiveSub_FallsThrough verifies
// behaviour (c): when the team has NO stored live subscription id (never paid,
// or a sub-id write that never landed), the guard cannot prove the event is
// stale, so it falls through to the historical downgrade behaviour.
func TestBillingWebhook_SubscriptionCancelled_EmptyLiveSub_FallsThrough(t *testing.T) {
	db, cleanDB := billingStateNeedsDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// stripe_customer_id left NULL (MustCreateTeamDB does not set it).
	payload := makeSubscriptionCancelledPayload(t, teamID, "sub_any_"+uuid.NewString())
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Historical behaviour: tier downgraded to the hobby courtesy floor.
	var newTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&newTier))
	assert.Equal(t, "hobby", newTier, "empty live sub must fall through to historical downgrade")

	// No stale-skip audit row — the guard did not trip.
	var staleCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid
		   AND kind = 'billing.charge_undeliverable'
		   AND metadata->>'reason' = 'stale_subscription_cancel'`, teamID).Scan(&staleCount))
	assert.Equal(t, 0, staleCount, "empty-live-sub fall-through must NOT emit a stale-skip audit row")
}
