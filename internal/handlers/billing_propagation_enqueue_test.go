package handlers_test

// billing_propagation_enqueue_test.go — regression coverage for the
// "user upgraded but downstream didn't propagate" event-driven retry
// mechanism (migration 058, propagation_runner worker job).
//
// THE INVARIANT
//   After handleSubscriptionCharged successfully commits the atomic
//   upgrade transaction (teams.plan_tier + resources.tier), it MUST
//   insert one row into pending_propagations:
//     - kind        = 'tier_elevation'
//     - team_id     = the upgraded team
//     - target_tier = the resolved tier
//     - applied_at  = NULL (the worker will stamp it)
//     - failed_at   = NULL
//     - attempts    = 0
//     - next_attempt_at <= now() (immediately eligible)
//
//   And it MUST be fail-open: an INSERT failure into pending_propagations
//   must NOT cause the webhook to 500, because the tier upgrade itself
//   has already committed. The entitlement_reconciler 5-min sweep is
//   the backstop.
//
// These tests are the surface checklist for migration 058 + the
// billing.go enqueue site (CLAUDE.md rules 16, 17, 22) — they live in
// the handlers package so they exercise the real webhook entrypoint, not
// a unit-level shim around the model.

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestBillingWebhook_ChargedInsertsPendingPropagation is the P0 invariant.
// A successful subscription.charged for a known team + plan_id MUST insert
// exactly one row into pending_propagations carrying the resolved tier,
// no terminal timestamp, and attempts=0.
func TestBillingWebhook_ChargedInsertsPendingPropagation(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_proppag_" + uuid.NewString()
	payload := makeChargedPayloadFull(t, teamID, subID, cfg.RazorpayPlanIDPro, 1, 0, "")

	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a successful charged event MUST return 200 — fail-open propagation enqueue must not break the upgrade")

	// Exactly one tier_elevation row for this team, in the "eligible for the
	// worker" state (no terminal timestamps, attempts=0, target_tier=pro).
	var (
		cnt              int
		targetTier       string
		appliedAtIsNull  bool
		failedAtIsNull   bool
		attempts         int
		nextAttemptDue   bool
	)
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pending_propagations
		 WHERE team_id = $1::uuid AND kind = 'tier_elevation'
	`, teamID).Scan(&cnt))
	assert.Equal(t, 1, cnt,
		"handleSubscriptionCharged must enqueue exactly ONE tier_elevation row per successful upgrade — got %d", cnt)

	require.NoError(t, db.QueryRow(`
		SELECT target_tier,
		       applied_at IS NULL,
		       failed_at IS NULL,
		       attempts,
		       next_attempt_at <= now()
		  FROM pending_propagations
		 WHERE team_id = $1::uuid AND kind = 'tier_elevation'
	`, teamID).Scan(&targetTier, &appliedAtIsNull, &failedAtIsNull, &attempts, &nextAttemptDue))

	assert.Equal(t, "pro", targetTier,
		"target_tier must be the SAME tier the api wrote to teams.plan_tier — got %q", targetTier)
	assert.True(t, appliedAtIsNull,
		"a freshly-enqueued row must have applied_at = NULL — got non-NULL, the worker would never pick it up")
	assert.True(t, failedAtIsNull,
		"a freshly-enqueued row must have failed_at = NULL — got non-NULL")
	assert.Equal(t, 0, attempts,
		"attempts must start at 0 — got %d", attempts)
	assert.True(t, nextAttemptDue,
		"next_attempt_at must be <= now() so the worker picks the row up on its next tick")
}

// TestBillingWebhook_ChargedPropagationInsertFailure_DoesNotBreakUpgrade is
// the fail-open invariant. We simulate a propagation INSERT failure by
// running the webhook against a DB whose pending_propagations table has been
// DROPped before the request. The webhook must still return 200 (the upgrade
// transaction committed BEFORE the propagation enqueue) and the team's
// plan_tier must be the new tier.
//
// This is the CLAUDE.md "must not fail the webhook" half of the contract.
// The runtime guard inside handleSubscriptionCharged is a loud slog.Error
// next to the failed INSERT; the entitlement_reconciler is still the
// 5-minute backstop that converges the infra eventually.
func TestBillingWebhook_ChargedPropagationInsertFailure_DoesNotBreakUpgrade(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// Drop pending_propagations so the propagation enqueue's INSERT returns
	// "relation does not exist" — the in-handler fail-open code path must
	// log loudly but NOT fail the webhook.
	if _, dropErr := db.Exec(`DROP TABLE IF EXISTS pending_propagations CASCADE`); dropErr != nil {
		t.Fatalf("DROP TABLE pending_propagations: %v", dropErr)
	}

	subID := "sub_propag_fail_" + uuid.NewString()
	payload := makeChargedPayloadFull(t, teamID, subID, cfg.RazorpayPlanIDPro, 1, 0, "")

	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	// FAIL-OPEN INVARIANT: the webhook must return 200 even though the
	// propagation insert failed. Otherwise Razorpay redelivers and the
	// committed upgrade re-fires the whole pipeline on every retry.
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a propagation INSERT failure MUST NOT 500 the webhook — the tier upgrade has already committed, and Razorpay redelivery cannot help (the next charged event would just hit the same failure)")

	// And the team's plan_tier MUST be the new tier — the atomic upgrade tx
	// ran BEFORE the propagation enqueue, so the user-visible state must
	// reflect the upgrade even when the eager retry path is broken.
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "pro", planTier,
		"teams.plan_tier MUST be the upgraded tier even when the propagation enqueue fails — the upgrade tx is the source of truth, the propagation row is a hint for the worker")
}
