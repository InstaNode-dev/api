package handlers_test

// billing_webhook_failure_signal_test.go — P1-W3-09 regression.
//
// Before the fix, the non-charged Razorpay webhook handlers
// (subscription.cancelled/halted/completed/paused/resumed, payment.failed)
// were `void`: they logged the failure and the dispatch switch fell through
// to a 200. Razorpay saw success, never redelivered — and because the dedup
// claim row was inserted up-front and never released, a replay was
// dedup-blocked too. A DB blip during subscription.cancelled meant the team
// kept its paid tier forever.
//
// The fix makes these handlers return an error; the dispatch switch releases
// the claim and returns 500 on a RETRYABLE failure (real DB/infra error), so
// Razorpay redelivers. A NON-retryable failure (missing/unknown-team payload)
// still keeps the claim and returns 200 — retrying a permanently-bad payload
// is pointless.
//
// These tests pin both halves of that contract.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
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

// TestBillingWebhook_SubscriptionCancelled_RetryableFailure_Returns500 is the
// core P1-W3-09 regression: when subscription.cancelled processing fails on a
// genuine infrastructure error (here, the platform DB is unreachable so the
// downgrade UPDATE errors), the webhook MUST return 500 so Razorpay
// redelivers. The pre-fix handler swallowed the failure and returned 200,
// permanently stranding the team on a paid tier.
func TestBillingWebhook_SubscriptionCancelled_RetryableFailure_Returns500(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}

	// Build the app against a real DB, then CLOSE the DB so every query the
	// handler runs returns a real "database is closed" error — a faithful
	// stand-in for the DB-blip scenario the bug describes.
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

	// A well-formed payload with a valid team_id in notes — team resolution
	// itself succeeds (no DB), but the downgrade UpdatePlanTier hits the
	// closed DB and errors → retryable failure.
	payload := makeSubscriptionCancelledPayload(t, uuid.NewString(), "sub_retry_"+uuid.NewString())
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_retry_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a retryable subscription.cancelled failure MUST return 500 so Razorpay redelivers — not a swallowed 200")
}

// TestBillingWebhook_SubscriptionCancelled_UnknownTeam_Returns200 pins the
// other half of the contract: a payload that can never resolve to a team
// (no notes.team_id and the subscription_id matches no team) is a permanent,
// non-retryable failure. It MUST still return 200 — retrying a payload that
// will never resolve just re-burns the dedup claim.
func TestBillingWebhook_SubscriptionCancelled_UnknownTeam_Returns200(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}
	app, cleanup := billingTestAppWithRealDB(t)
	defer cleanup()

	// sub_id present but matches no team; no team_id in notes →
	// resolveTeamFromNotes returns ErrTeamNotFound → non-retryable.
	payload := makeSubscriptionCancelledPayload(t, "", "sub_unknown_"+uuid.NewString())
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", "evt_unknown_"+uuid.NewString())

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"an unknown-team subscription.cancelled is non-retryable — keep the claim, return 200")
}

// testhelpersSkipNoDB skips the calling test (returning true) when no test DB
// is configured, matching the requireDB pattern used across the suite.
func testhelpersSkipNoDB(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed webhook failure-signal test")
		return true
	}
	return false
}
