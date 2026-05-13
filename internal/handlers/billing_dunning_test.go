package handlers_test

// billing_dunning_test.go — webhook-side coverage for the dunning state
// machine. Mirrors the existing audit-emit tests in billing_test.go:
// real Postgres, signed Razorpay payloads, assertions against the
// committed DB state + audit_log rows.
//
// Two flows under test:
//   1. subscription.charged_failed → INSERT grace row + audit emit.
//      Redelivery hits the partial-unique index and silently no-ops.
//   2. subscription.charged during active grace → flip grace to
//      'recovered' + audit emit. Renewal without prior grace is a
//      no-op (no audit row).
//
// The destructive terminator job + the 6h reminder cadence both live
// in the worker repo (separate PR per the brief); this file does not
// exercise them.

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// makeSubscriptionChargeFailedPayload builds a Razorpay
// subscription.charged_failed webhook payload. teamID is stamped into
// notes.team_id so resolveTeamFromNotes finds the team without an
// auxiliary DB lookup. The optional `payment` payload mirrors what
// Razorpay actually sends — both entities co-exist on a failed-charge
// event — so the handler's attempted-amount extraction is exercised.
func makeSubscriptionChargeFailedPayload(t *testing.T, teamID, subscriptionID string, attemptedAmount int64) []byte {
	t.Helper()
	subEntity, _ := json.Marshal(map[string]any{
		"id":      subscriptionID,
		"entity":  "subscription",
		"plan_id": "plan_test_pro",
		"status":  "halted",
		"notes":   map[string]any{"team_id": teamID},
	})
	payment := map[string]any{
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	if attemptedAmount > 0 {
		payEntity, _ := json.Marshal(map[string]any{
			"id":                "pay_failed_" + uuid.NewString(),
			"entity":            "payment",
			"amount":            attemptedAmount,
			"currency":          "INR",
			"attempt_count":     3,
			"error_description": "Card declined",
		})
		payment["payload"].(map[string]any)["payment"] = map[string]any{
			"entity": json.RawMessage(payEntity),
		}
	}
	event := map[string]any{
		"entity":  "event",
		"event":   "subscription.charged_failed",
		"payload": payment["payload"],
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeSubscriptionChargeFailedPayload: %v", err)
	}
	return payload
}

// dunningWebhookSkipUnlessDB protects DB-dependent dunning tests from
// firing without a configured test Postgres — matches the existing
// pattern from billing_test.go's GetBillingState tests.
func dunningWebhookSkipUnlessDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing dunning tests: TEST_DATABASE_URL not set")
	}
}

// TestBillingWebhook_ChargeFailed_OpensGracePeriod is the dunning
// happy-path: a charge_failed event arrives, the handler creates one
// active grace row + emits one payment.grace_started audit row. Webhook
// returns 200. Tier is unchanged (grace start does not downgrade the
// team — that only happens at termination, 7 days later, in the worker).
func TestBillingWebhook_ChargeFailed_OpensGracePeriod(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_test_" + uuid.NewString()
	payload := makeSubscriptionChargeFailedPayload(t, teamID, subID, 4100_00)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// One active grace row.
	var status, subscriptionID string
	require.NoError(t, db.QueryRow(`
		SELECT status, subscription_id
		  FROM payment_grace_periods
		 WHERE team_id = $1::uuid`,
		teamID).Scan(&status, &subscriptionID))
	assert.Equal(t, "active", status)
	assert.Equal(t, subID, subscriptionID)

	// Tier remains pro — grace start does not downgrade.
	var planTier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&planTier))
	assert.Equal(t, "pro", planTier, "tier must not change on grace start")

	// One payment.grace_started audit row with the expected metadata.
	var kind, summary, metaText string
	require.NoError(t, db.QueryRow(`
		SELECT kind, summary, metadata::text
		  FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'payment.grace_started'
		 ORDER BY created_at DESC LIMIT 1`,
		teamID).Scan(&kind, &summary, &metaText))
	assert.Equal(t, "payment.grace_started", kind)
	assert.Contains(t, summary, "grace")
	meta := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(metaText), &meta))
	assert.Equal(t, subID, meta["subscription_id"])
	assert.NotEmpty(t, meta["grace_id"])
	assert.NotEmpty(t, meta["expires_at"])
	// Attempted amount was non-zero (4100_00 paise) — must serialise.
	require.NotNil(t, meta["attempted_amount"])
}

// TestBillingWebhook_ChargeFailed_RedeliveryIsNoop verifies the
// idempotency contract: Razorpay redelivers the same charge_failed
// event, the handler hits the partial-unique index, and we end up with
// exactly one active grace row + exactly one audit row. This is the
// production-critical guarantee — without it, redelivery would double
// the reminder email cadence.
func TestBillingWebhook_ChargeFailed_RedeliveryIsNoop(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_test_" + uuid.NewString()
	payload := makeSubscriptionChargeFailedPayload(t, teamID, subID, 4100_00)

	// First delivery.
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	resp.Body.Close()

	// Second delivery (Razorpay redelivery) — same payload, same signature.
	resp, err = app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "redelivery must still 200")

	// Exactly ONE active grace row.
	var graceCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`,
		teamID).Scan(&graceCount))
	assert.Equal(t, 1, graceCount, "redelivery must not create a second grace row")

	// And exactly ONE audit row — the second delivery's ErrPaymentGraceAlreadyActive
	// path skips the emit, so the Brevo forwarder doesn't double-send.
	var auditCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'payment.grace_started'`,
		teamID).Scan(&auditCount))
	assert.Equal(t, 1, auditCount, "redelivery must not double-emit the started audit row")
}

// TestBillingWebhook_ChargedDuringGrace_FlipsToRecovered covers the
// recovery flow: subscription.charged arrives while an active grace
// row exists. The handler flips the grace row to 'recovered' and emits
// a payment.grace_recovered audit row. The tier elevation in
// handleSubscriptionCharged still lands.
func TestBillingWebhook_ChargedDuringGrace_FlipsToRecovered(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_test_" + uuid.NewString()

	// Seed an active grace row via the webhook (same path the customer
	// hits in production — keeps the test honest about end-to-end shape).
	resp, err := app.Test(signedWebhookRequest(t,
		makeSubscriptionChargeFailedPayload(t, teamID, subID, 4100_00)), 5000)
	require.NoError(t, err)
	resp.Body.Close()

	// Customer's card recovers — subscription.charged arrives.
	resp, err = app.Test(signedWebhookRequest(t,
		makeSubscriptionChargedPayloadWithPlan(t, teamID, subID, cfg.RazorpayPlanIDPro)), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Grace row flipped to 'recovered'.
	var status string
	var recoveredAt *string // accept NULL or value
	require.NoError(t, db.QueryRow(`
		SELECT status, recovered_at::text FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamID).Scan(&status, &recoveredAt))
	assert.Equal(t, "recovered", status)
	require.NotNil(t, recoveredAt, "recovered_at must populate")

	// Exactly one payment.grace_recovered audit row.
	var kind, metaText string
	require.NoError(t, db.QueryRow(`
		SELECT kind, metadata::text FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'payment.grace_recovered'
		 ORDER BY created_at DESC LIMIT 1`,
		teamID).Scan(&kind, &metaText))
	assert.Equal(t, "payment.grace_recovered", kind)
	meta := map[string]any{}
	require.NoError(t, json.Unmarshal([]byte(metaText), &meta))
	assert.Equal(t, subID, meta["subscription_id"])
}

// TestBillingWebhook_ChargedWithoutGrace_NoRecoveryAuditRow covers the
// normal monthly-renewal case: subscription.charged with no prior
// charge_failed. The handler must NOT emit a payment.grace_recovered
// audit row — that would trigger a "back in good standing" email
// every billing cycle, which is wrong.
func TestBillingWebhook_ChargedWithoutGrace_NoRecoveryAuditRow(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	resp, err := app.Test(signedWebhookRequest(t,
		makeSubscriptionChargedPayloadWithPlan(t, teamID, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro)), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var count int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'payment.grace_recovered'`,
		teamID).Scan(&count))
	assert.Equal(t, 0, count, "happy-path renewal must NOT emit grace_recovered")
}

// TestBillingWebhook_ChargeFailed_CrossTeamIsolation guards against
// the disastrous failure mode where a charge_failed for team A
// inadvertently opens a grace row on team B (or both). We seed two
// teams, fail-charge one, and verify only that team has the grace
// row + the audit row.
func TestBillingWebhook_ChargeFailed_CrossTeamIsolation(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamA := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamB := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = ANY($1::uuid[])`, "{"+teamA+","+teamB+"}")

	resp, err := app.Test(signedWebhookRequest(t,
		makeSubscriptionChargeFailedPayload(t, teamA, "sub_test_"+uuid.NewString(), 4100_00)), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Team A has one active grace row.
	var aCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`,
		teamA).Scan(&aCount))
	assert.Equal(t, 1, aCount)

	// Team B has none.
	var bCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid`,
		teamB).Scan(&bCount))
	assert.Equal(t, 0, bCount, "team B must not see team A's grace row")

	// And only team A has the audit row.
	var aAudit, bAudit int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'payment.grace_started'`, teamA).Scan(&aAudit))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'payment.grace_started'`, teamB).Scan(&bAudit))
	assert.Equal(t, 1, aAudit)
	assert.Equal(t, 0, bAudit)
}

// TestBillingWebhook_ChargeFailed_FailOpen_AuditMissDoesNotRollBackGrace
// verifies the fail-open contract on the audit emit path. We drop the
// audit_log table, fire the webhook, and assert:
//   - the webhook still 200s (Razorpay must not retry on an audit
//     failure),
//   - the grace row still landed (the state machine is the source of
//     truth, not the audit row).
//
// Restoring the table in defer keeps subsequent tests usable.
func TestBillingWebhook_ChargeFailed_FailOpen_AuditMissDoesNotRollBackGrace(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	_, err := db.Exec(`DROP TABLE IF EXISTS audit_log CASCADE`)
	require.NoError(t, err)
	defer db.Exec(`CREATE TABLE IF NOT EXISTS audit_log (
		id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		team_id       UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
		user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
		actor         TEXT NOT NULL DEFAULT 'agent',
		kind          TEXT NOT NULL,
		resource_type TEXT,
		resource_id   UUID,
		summary       TEXT NOT NULL,
		metadata      JSONB,
		created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)

	resp, err := app.Test(signedWebhookRequest(t,
		makeSubscriptionChargeFailedPayload(t, teamID, "sub_test_"+uuid.NewString(), 4100_00)), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "audit miss must not turn the webhook into a 4xx/5xx")

	// Grace row landed despite the audit miss.
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`, teamID).Scan(&count))
	assert.Equal(t, 1, count, "grace row must commit even when audit emit fails (fail-open contract)")
}
