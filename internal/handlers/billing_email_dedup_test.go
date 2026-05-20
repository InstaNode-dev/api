package handlers_test

// billing_email_dedup_test.go — EMAIL-BUGBASH C4/C5/F2 regression tests.
//
// Drives the Razorpay webhook against a real platform DB and a Brevo-backed
// email.Client wired to a fake Brevo server that COUNTS outbound sends. The
// pre-fix bug: two distinct Razorpay events for one billing cycle each fired
// an email (two receipts on activated+charged; two dunning notices on
// payment.failed+subscription.pending). These tests assert one cycle = one
// email.
//
// DB-backed: skipped when TEST_DATABASE_URL is unset.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// emailDedupApp wires a billing webhook app against db with a Brevo-backed
// email client pointed at a counting fake server.
func emailDedupApp(t *testing.T) (*fiber.App, *int64, func()) {
	t.Helper()
	database, cleanup := testhelpers.SetupTestDB(t)

	var sendCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&sendCount, 1)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	rewrite := &urlRewriter{base: srv.URL, inner: http.DefaultTransport}
	emailClient := email.New(email.Config{
		Provider:    "brevo",
		BrevoAPIKey: "xkeysib-test",
		HTTPClient:  &http.Client{Transport: rewrite},
	})

	cfg := &config.Config{
		JWTSecret:             testhelpers.TestJWTSecret,
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDPro:     "plan_test_pro",
	}
	bh := handlers.NewBillingHandler(database, cfg, emailClient)
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)
	return app, &sendCount, cleanup
}

// urlRewriter mirrors the email package test helper: swaps scheme+host of an
// outbound request with the fake server's so the Brevo provider can target a
// httptest.Server without monkey-patching the package endpoint constant.
type urlRewriter struct {
	base  string
	inner http.RoundTripper
}

func (u *urlRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	idx := indexOf(u.base, "://")
	if idx > 0 {
		req.URL.Scheme = u.base[:idx]
		req.URL.Host = u.base[idx+3:]
	}
	return u.inner.RoundTrip(req)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// makeChargedPayloadWithPaidCount builds a subscription event (activated or
// charged) carrying a paid_count + an event id + an optional payment entity.
// paid_count is the per-cycle anchor the receipt dedup key uses.
func makeChargedPayloadWithPaidCount(t *testing.T, eventType, eventID, teamID, subID string, paidCount int64, withPayment bool) []byte {
	t.Helper()
	subEntity, _ := json.Marshal(map[string]any{
		"id":         subID,
		"entity":     "subscription",
		"plan_id":    "plan_test_pro",
		"status":     "active",
		"notes":      map[string]any{"team_id": teamID},
		"paid_count": paidCount,
	})
	payload := map[string]any{
		"subscription": map[string]any{"entity": json.RawMessage(subEntity)},
	}
	if withPayment {
		payEntity, _ := json.Marshal(map[string]any{
			"id": "pay_" + uuid.NewString()[:12], "entity": "payment",
			"amount": int64(490000), "currency": "INR", "status": "captured",
		})
		payload["payment"] = map[string]any{"entity": json.RawMessage(payEntity)}
	}
	event := map[string]any{
		"id": eventID, "entity": "event", "event": eventType, "payload": payload,
	}
	b, err := json.Marshal(event)
	require.NoError(t, err)
	return b
}

// TestBillingWebhook_ReceiptDedup_OneCycleOneEmail is the EMAIL-BUGBASH C4
// regression test. subscription.activated and subscription.charged are two
// DISTINCT Razorpay events (distinct event_ids, so the replay guard does not
// collapse them) — both route into sendPaymentReceipt. Without the per-cycle
// dedup key the customer gets TWO receipt emails. After the fix: exactly one.
func TestBillingWebhook_ReceiptDedup_OneCycleOneEmail(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	app, sendCount, cleanup := emailDedupApp(t)
	defer cleanup()

	// Reuse the package DB handle via a fresh team — emailDedupApp already
	// ran migrations; seed a paid team + owner through a new connection is
	// unnecessary, MustCreateTeamDB works on the same DSN.
	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	_, err := db.Exec(
		`INSERT INTO users (team_id, email, role) VALUES ($1::uuid, $2, 'owner')`,
		teamID, "receipt-"+uuid.NewString()[:8]+"@example.com")
	require.NoError(t, err)

	subID := "sub_receipt_" + uuid.NewString()

	// Event 1: subscription.activated for cycle paid_count=1.
	p1 := makeChargedPayloadWithPaidCount(t, "subscription.activated",
		"evt_act_"+uuid.NewString(), teamID, subID, 1, false)
	resp1, err := app.Test(signedWebhookRequest(t, p1), 5000)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Event 2: subscription.charged for the SAME cycle paid_count=1.
	p2 := makeChargedPayloadWithPaidCount(t, "subscription.charged",
		"evt_chg_"+uuid.NewString(), teamID, subID, 1, true)
	resp2, err := app.Test(signedWebhookRequest(t, p2), 5000)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	got := atomic.LoadInt64(sendCount)
	assert.Equal(t, int64(1), got,
		"C4: subscription.activated + subscription.charged for one billing cycle must send exactly ONE receipt email, got %d", got)
}

// TestBillingWebhook_DunningDedup_OneCycleOneEmail is the EMAIL-BUGBASH C5
// regression test. payment.failed and subscription.pending are two distinct
// Razorpay events for one failed billing cycle — both call SendPaymentFailed.
// Without the dedup key the customer gets TWO dunning emails. After the fix:
// exactly one.
func TestBillingWebhook_DunningDedup_OneCycleOneEmail(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	app, sendCount, cleanup := emailDedupApp(t)
	defer cleanup()

	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	owner := "dunning-" + uuid.NewString()[:8] + "@example.com"
	// B11-P1: dunning recipient is now resolved via the team's primary
	// user, not the payload email — owner row MUST be is_primary=true so
	// GetPrimaryUserByTeamID finds it.
	_, err := db.Exec(
		`INSERT INTO users (team_id, email, role, is_primary) VALUES ($1::uuid, $2, 'owner', true)`,
		teamID, owner)
	require.NoError(t, err)

	// Event 1: payment.failed carrying the owner's address + notes.team_id.
	// B11-P1: payload.email is no longer trusted; the resolver uses
	// notes.team_id → team primary user. Without the WithTeam variant
	// (which threads notes.team_id), the dunning email would be DROPPED
	// rather than mis-delivered — also a valid B11-P1 outcome, but the
	// dedup contract this test pins requires a successful send.
	pf := makePaymentFailedPayloadWithEventIDAndTeam(t, "evt_pf_"+uuid.NewString(), owner, teamID)
	resp1, err := app.Test(signedWebhookRequest(t, pf), 5000)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Event 2: subscription.pending for the same team — resolves to the same
	// owner email, same dunning dedup key for today.
	sp := makeSubscriptionPendingPayload(t, teamID, "sub_pending_"+uuid.NewString())
	resp2, err := app.Test(signedWebhookRequest(t, sp), 5000)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	got := atomic.LoadInt64(sendCount)
	assert.Equal(t, int64(1), got,
		"C5: payment.failed + subscription.pending for one failed cycle must send exactly ONE dunning email, got %d", got)
}

// TestBillingWebhook_AdminCancel_NoDoubleAudit is the EMAIL-BUGBASH F2
// regression test. An admin demote emits a subscription.canceled_by_admin
// audit row AND triggers a Razorpay cancel that fires a subscription.cancelled
// webhook. Pre-fix, handleSubscriptionCancelled then emitted a SECOND
// subscription.canceled audit row → the customer got two cancellation emails.
// After the fix: when a fresh canceled_by_admin row exists, the webhook path
// skips its emit, so no second subscription.canceled row is written.
func TestBillingWebhook_AdminCancel_NoDoubleAudit(t *testing.T) {
	dunningWebhookSkipUnlessDB(t)
	app, _, cleanup := emailDedupApp(t)
	defer cleanup()

	db, dbClean := testhelpers.SetupTestDB(t)
	defer dbClean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	subID := "sub_admincancel_" + uuid.NewString()

	// Simulate the admin-demote half: a subscription.canceled_by_admin audit
	// row already exists for this team (the admin path emits it + sends its
	// own cancellation email).
	_, err := db.Exec(
		`INSERT INTO audit_log (team_id, actor, kind, summary)
		 VALUES ($1::uuid, 'admin', 'subscription.canceled_by_admin', 'admin demoted customer')`,
		teamID)
	require.NoError(t, err)

	// Now the Razorpay subscription.cancelled webhook (the echo of the admin
	// cancel) arrives.
	payload := makeSubscriptionCancelledPayload(t, teamID, subID)
	resp, err := app.Test(signedWebhookRequest(t, payload), 5000)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// The webhook path must NOT have emitted a second subscription.canceled
	// audit row — that row drives the duplicate cancellation email.
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'subscription.canceled'`,
		teamID).Scan(&n))
	assert.Equal(t, 0, n,
		"F2: with a fresh subscription.canceled_by_admin row, the webhook path must NOT emit a duplicate subscription.canceled audit row")
}
