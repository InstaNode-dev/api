package handlers_test

// billing_p2p3_audit_test.go — regression coverage for the BILLING-TRUST-AUDIT
// 2026-05-19 P2/P3 findings F9, F10, F11. Each test FAILS without the matching
// fix and PASSES with it.
//
//	F9  (P3) — emitSubscriptionChangeAudit must be idempotent on
//	           (team_id, kind, subscription_id). The webhook's up-front dedup
//	           claim is fail-open; if the claim INSERT errors during a DB
//	           brownout, two concurrent deliveries of the same
//	           subscription.charged event both dispatch. Both snapshot the
//	           same pre-upgrade fromTier, so both emit a subscription.upgraded
//	           audit row → a duplicate upgrade-confirmation email. After the
//	           fix the second emit is a no-op.
//	F10 (P2) — handleSubscriptionChargeFailed must follow the same retry
//	           contract as the other webhook handlers: a transient/retryable
//	           failure (here, the platform DB is unreachable so the grace-row
//	           INSERT errors) returns 500 so Razorpay redelivers. Pre-fix the
//	           handler was void and the dispatch fell through to a swallowed
//	           200, suppressing redelivery.
//	F11 (P3) — the subscription.canceled audit row's Summary copy must state
//	           the accurate outcome (account stays on a courtesy floor /
//	           moves to free, resources keep their limits, an in-flight cycle
//	           charge still completes) — not the bare, misleading
//	           "subscription canceled".
//
// DB-backed tests run against a real test Postgres (skipped cleanly when
// TEST_DATABASE_URL is unset, matching the rest of the suite). The F10
// retryable-failure test deliberately closes the DB so every query errors —
// the same faithful stand-in used by billing_webhook_failure_signal_test.go.

import (
	"bytes"
	"encoding/json"
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

// ── F10 ─────────────────────────────────────────────────────────────────────

// TestBillingWebhook_ChargeFailed_RetryableFailure_Returns500 is the F10 P2
// regression. A subscription.charged_failed event carries a resolvable
// notes.team_id, so team resolution succeeds without a DB call — but the
// grace-row INSERT then runs against a closed DB and returns a real
// (retryable) error. The handler must propagate that so the webhook releases
// the dedup claim and returns 500, letting Razorpay redeliver. Pre-fix the
// handler was void: it logged the failure and the dispatch fell through to a
// swallowed 200, suppressing redelivery (the first dunning email was then up
// to ~15 min late, waiting on the reconciler).
func TestBillingWebhook_ChargeFailed_RetryableFailure_Returns500(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}

	// Build the app against a real DB, then CLOSE it so every query errors —
	// a faithful stand-in for the DB-blip scenario the finding describes.
	db, dbCleanup := testhelpers.SetupTestDB(t)
	dbCleanup() // close immediately — subsequent queries error.

	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
	}
	billing := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	// A real (valid) team_id in notes → resolveTeamFromNotes succeeds with no
	// DB call → the handler proceeds to startGracePeriodForTeam, whose INSERT
	// hits the closed DB and errors. That is the retryable path.
	payload := makeSubscriptionChargeFailedPayload(t, uuid.NewString(),
		"sub_chargefail_"+uuid.NewString(), 4100_00)
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_chargefail_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a retryable failure (grace-row INSERT against a dead DB) during subscription.charged_failed MUST return 500 so Razorpay redelivers — not a swallowed 200 (F10)")
}

// TestBillingWebhook_ChargeFailed_Success_Returns200 is the F10 negative
// control: the corrected handler still returns 200 on the happy path — a
// healthy charge_failed opens the grace period and the webhook acknowledges.
// The retry contract must not turn a successful dunning open into a 500.
func TestBillingWebhook_ChargeFailed_Success_Returns200(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := makeSubscriptionChargeFailedPayload(t, teamID,
		"sub_chargefail_ok_"+uuid.NewString(), 4100_00)
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a successful charge_failed dunning-open must still 200 — the F10 retry contract must not 500 the happy path")

	var graceCount int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`,
		teamID).Scan(&graceCount))
	assert.Equal(t, 1, graceCount, "the happy path must still open exactly one active grace row")
}

// ── F9 ──────────────────────────────────────────────────────────────────────

// TestBillingWebhook_ChargedRace_EmitsSingleUpgradeAudit is the F9 P3
// regression. The webhook's up-front dedup claim is fail-open: if the claim
// INSERT itself errors during a DB brownout, two concurrent deliveries of the
// same subscription.charged event both dispatch handleSubscriptionCharged.
// Both deliveries snapshot fromTier BEFORE either UpgradeTeamAllTiers commits,
// so both read the SAME pre-upgrade tier (free) and both compute the identical
// free→pro transition → without the F9 guard each calls
// emitSubscriptionChangeAudit and inserts a subscription.upgraded audit row →
// the worker forwarder sends two upgrade-confirmation emails for one upgrade.
//
// A purely serial double-delivery would NOT reproduce this: the second
// delivery reads the already-upgraded tier (pro) and emitSubscriptionChangeAudit
// no-ops on the fromR == toR guard. To faithfully reproduce the race — both
// deliveries seeing fromTier=free — the team's plan_tier is reset to 'free'
// between the two deliveries (and the event-id header is omitted, the genuine
// fail-open "no dedup claim" shape). Both deliveries then run the free→pro
// emit. The F9 fix makes the second emit idempotent on
// (team_id, kind, subscription_id): the audit_log must hold exactly ONE
// subscription.upgraded row for the subscription.
func TestBillingWebhook_ChargedRace_EmitsSingleUpgradeAudit(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, cfg := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_f9_" + uuid.NewString()
	payload := makeChargedPayloadFull(t, teamID, subID, cfg.RazorpayPlanIDPro, 1, 0, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)

	// deliverNoEventID posts the charged payload WITHOUT the event-id header,
	// reproducing the fail-open "no dedup claim" window. The per-request
	// timeout is generous (30s) — a charged delivery runs the full
	// UpgradeTeamAllTiers transaction + receipt lookup.
	deliverNoEventID := func() {
		req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Razorpay-Signature", sig)
		resp, err := app.Test(req, 30000)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	deliverNoEventID()
	// Reset the tier so the SECOND delivery snapshots fromTier=free too —
	// the exact state both racing deliveries observe before either commits.
	_, err := db.Exec(`UPDATE teams SET plan_tier = 'free' WHERE id = $1::uuid`, teamID)
	require.NoError(t, err)
	deliverNoEventID()

	// Exactly ONE subscription.upgraded audit row for this subscription — the
	// F9 idempotency guard suppressed the duplicate from the second delivery.
	var upgradeAudits int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM audit_log
		 WHERE team_id = $1::uuid
		   AND kind = 'subscription.upgraded'
		   AND metadata->>'subscription_id' = $2`,
		teamID, subID).Scan(&upgradeAudits))
	assert.Equal(t, 1, upgradeAudits,
		"two concurrent deliveries of the same charged event must emit exactly ONE subscription.upgraded audit row — the F9 fix dedups on (team_id, kind, subscription_id)")
}

// ── F11 ─────────────────────────────────────────────────────────────────────

// TestBillingWebhook_Cancelled_AuditSummaryStatesAccurateOutcome is the F11 P3
// regression. The subscription.canceled audit row's Summary is rendered
// verbatim by the dashboard's Recent Activity feed and is the api-side source
// of truth for the worker's cancellation email. The pre-fix copy was the bare
// "subscription canceled" — misleading by omission: it never told the customer
// the account stays active on a courtesy floor and that an in-flight cycle
// charge will still complete. A customer could mistake the next charge for
// fraud. After the fix the rendered Summary states the accurate outcome.
//
// This drives a real subscription.cancelled webhook (paid_count > 0 → the
// 'hobby' courtesy floor) and asserts the persisted audit Summary + metadata.
func TestBillingWebhook_Cancelled_AuditSummaryStatesAccurateOutcome(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	app, _ := billingWebhookDBApp(t, db)

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	// paid_count = 6 → the team paid at least once → courtesy 'hobby' floor.
	payload := makeSubscriptionLifecyclePayload(t, "subscription.cancelled",
		teamID, "sub_f11_"+uuid.NewString(), 6)
	postLifecycleWebhook(t, app, payload)

	var summary, metaText string
	require.NoError(t, db.QueryRow(`
		SELECT summary, metadata::text
		  FROM audit_log
		 WHERE team_id = $1::uuid AND kind = 'subscription.canceled'
		 ORDER BY created_at DESC LIMIT 1`,
		teamID).Scan(&summary, &metaText))

	// The corrected wording must NOT be the bare misleading string.
	assert.NotEqual(t, "subscription canceled", strings.ToLower(strings.TrimSpace(summary)),
		"the cancellation Summary must no longer be the bare, misleading 'subscription canceled' (F11)")
	// It must state the account stays active on the courtesy floor...
	lower := strings.ToLower(summary)
	assert.Contains(t, lower, "hobby",
		"the cancellation copy must name the courtesy floor tier the account drops to (F11)")
	assert.Contains(t, lower, "current limits",
		"the cancellation copy must tell the customer existing resources keep their limits (F11)")
	// ...and that an in-flight cycle charge is expected, not an error.
	assert.Contains(t, lower, "billing cycle",
		"the cancellation copy must warn that an in-flight cycle charge will still complete so it is not mistaken for fraud (F11)")

	// The same accurate text must be mirrored into the audit metadata under
	// effective_note so the worker's cancellation email can render it.
	meta := map[string]string{}
	require.NoError(t, json.Unmarshal([]byte(metaText), &meta))
	assert.Equal(t, summary, meta["effective_note"],
		"the cancellation audit metadata must carry the accurate effective_note copy for the email renderer (F11)")
}
