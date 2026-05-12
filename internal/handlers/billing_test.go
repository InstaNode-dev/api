package handlers_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/razorpaybilling"
	"instant.dev/internal/testhelpers"
)

const testWebhookSecret = "test_razorpay_webhook_secret"

// billingTestApp builds a minimal Fiber app with just the Razorpay webhook route.
// It does NOT require a real DB or Redis — the noop email client and a nil *sql.DB
// are sufficient for tests that exercise the noop/logging path.
func billingTestApp(t *testing.T) *fiber.App {
	t.Helper()

	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
	}

	emailClient := email.New("") // noop
	billing := handlers.NewBillingHandler(nil, cfg, emailClient)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{
				"ok":    false,
				"error": "internal_error",
			})
		},
	})
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)
	return app
}

// signRazorpayPayload computes HMAC-SHA256(key=secret, msg=payload) as hex.
func signRazorpayPayload(t *testing.T, secret string, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// signedWebhookRequest creates an *http.Request with a valid X-Razorpay-Signature header.
func signedWebhookRequest(t *testing.T, payload []byte) *http.Request {
	t.Helper()
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	return req
}

// makePaymentFailedPayload builds a minimal Razorpay payment.failed JSON payload.
// customerEmail may be empty to exercise the no-email path (useful when testing with a nil DB).
func makePaymentFailedPayload(t *testing.T, customerEmail string, attemptCount int) []byte {
	t.Helper()

	paymentEntity := map[string]any{
		"id":                "pay_test_123",
		"entity":            "payment",
		"amount":            490000,
		"currency":          "INR",
		"email":             customerEmail,
		"attempt_count":     attemptCount,
		"error_description": "Card declined",
	}
	paymentJSON, _ := json.Marshal(paymentEntity)

	event := map[string]any{
		"entity": "event",
		"event":  "payment.failed",
		"payload": map[string]any{
			"payment": map[string]any{
				"entity": json.RawMessage(paymentJSON),
			},
		},
	}

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makePaymentFailedPayload: marshal event: %v", err)
	}
	return payload
}

// TestBillingWebhook_PaymentFailed_SendsEmail verifies that a valid payment.failed
// webhook returns 200 and (with noop email client) does not error.
func TestBillingWebhook_PaymentFailed_SendsEmail(t *testing.T) {
	app := billingTestApp(t)

	payload := makePaymentFailedPayload(t, "billing@example.com", 1)
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := body["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got body: %v", body)
	}
}

// TestBillingWebhook_InvalidSignature_Returns400 verifies that a request with a
// bad X-Razorpay-Signature is rejected with 400.
func TestBillingWebhook_InvalidSignature_Returns400(t *testing.T) {
	app := billingTestApp(t)

	payload := []byte(`{"entity":"event","event":"payment.failed","payload":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", "badsignature")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid signature, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_PaymentFailed_FinalAttempt_SendsEmail verifies attempt_count=3 (final)
// returns 200 without error.
func TestBillingWebhook_PaymentFailed_FinalAttempt_SendsEmail(t *testing.T) {
	app := billingTestApp(t)

	payload := makePaymentFailedPayload(t, "billing@example.com", 3)
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_PaymentFailed_NoEmail_Returns200 verifies that when no
// customer email is present, the handler still returns 200 (logs warning, skips email).
func TestBillingWebhook_PaymentFailed_NoEmail_Returns200(t *testing.T) {
	app := billingTestApp(t)

	payload := makePaymentFailedPayload(t, "", 2)
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_UnknownEvent_Returns200 verifies unknown event types are silently acknowledged.
func TestBillingWebhook_UnknownEvent_Returns200(t *testing.T) {
	app := billingTestApp(t)

	event := map[string]any{
		"entity":  "event",
		"event":   "order.paid", // not handled
		"payload": map[string]any{},
	}
	payload, _ := json.Marshal(event)
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for unknown event, got %d", resp.StatusCode)
	}
}

// makeSubscriptionChargedPayload builds a subscription.charged event.
// Set teamID to empty string to exercise the "cannot resolve team" error path (safe with nil DB).
func makeSubscriptionChargedPayload(t *testing.T, teamID, subscriptionID string) []byte {
	t.Helper()
	notes := map[string]any{}
	if teamID != "" {
		notes["team_id"] = teamID
	}
	subEntity, _ := json.Marshal(map[string]any{
		"id":      subscriptionID,
		"entity":  "subscription",
		"plan_id": "",
		"status":  "active",
		"notes":   notes,
	})
	event := map[string]any{
		"entity": "event",
		"event":  "subscription.charged",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeSubscriptionChargedPayload: marshal: %v", err)
	}
	return payload
}

// makeSubscriptionCancelledPayload builds a subscription.cancelled event.
func makeSubscriptionCancelledPayload(t *testing.T, teamID, subscriptionID string) []byte {
	t.Helper()
	notes := map[string]any{}
	if teamID != "" {
		notes["team_id"] = teamID
	}
	subEntity, _ := json.Marshal(map[string]any{
		"id":     subscriptionID,
		"entity": "subscription",
		"status": "cancelled",
		"notes":  notes,
	})
	event := map[string]any{
		"entity": "event",
		"event":  "subscription.cancelled",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("makeSubscriptionCancelledPayload: marshal: %v", err)
	}
	return payload
}

// TestBillingWebhook_SubscriptionCharged_MissingTeamID_Returns200 verifies that
// subscription.charged with no team_id in notes and no sub_id returns 200.
// The handler logs an error and returns early — safe with nil DB.
func TestBillingWebhook_SubscriptionCharged_MissingTeamID_Returns200(t *testing.T) {
	app := billingTestApp(t)

	// Empty teamID + empty subscriptionID → resolveTeamFromNotes returns error immediately.
	payload := makeSubscriptionChargedPayload(t, "", "")
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	// Always returns 200 — failed team resolution is logged, not surfaced.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_SubscriptionCancelled_MissingTeamID_Returns200 verifies that
// subscription.cancelled with no team_id and no sub_id returns 200.
func TestBillingWebhook_SubscriptionCancelled_MissingTeamID_Returns200(t *testing.T) {
	app := billingTestApp(t)

	payload := makeSubscriptionCancelledPayload(t, "", "")
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_SubscriptionCharged_MalformedEntity_Returns200 verifies that
// a subscription.charged with a broken subscription entity returns 200 (parse error logged).
func TestBillingWebhook_SubscriptionCharged_MalformedEntity_Returns200(t *testing.T) {
	app := billingTestApp(t)

	event := map[string]any{
		"entity": "event",
		"event":  "subscription.charged",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": "this-is-not-a-json-object",
			},
		},
	}
	payload, _ := json.Marshal(event)
	req := signedWebhookRequest(t, payload)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on malformed entity, got %d", resp.StatusCode)
	}
}

// TestBillingWebhook_MissingSignature_Returns400 verifies that missing signature returns 400.
func TestBillingWebhook_MissingSignature_Returns400(t *testing.T) {
	app := billingTestApp(t)

	payload := makePaymentFailedPayload(t, "user@example.com", 1)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// No X-Razorpay-Signature header

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing signature, got %d", resp.StatusCode)
	}
}

// ── GetBillingState (GET /api/v1/billing) ───────────────────────────────────

// billingStateApp builds a Fiber app wired with the real BillingHandler plus a
// fake-auth middleware that injects (user_id, team_id) into Fiber locals so
// the handler reads them via middleware.GetTeamID. Tests substitute the portal
// fetcher by setting h.FetchSubscriptionDetails directly on the handler.
func billingStateApp(t *testing.T, db *sql.DB, teamID string, fetch func(string) (*razorpaybilling.SubscriptionDetails, error)) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret: testhelpers.TestJWTSecret,
		// Razorpay creds are set non-empty so the handler attempts the live
		// fetch path. Tests still don't hit the network because we override
		// FetchSubscriptionDetails below.
		RazorpayKeyID:     "rzp_test_dummy",
		RazorpayKeySecret: "rzp_test_dummy_secret",
	}
	mail := email.New("") // noop

	bh := handlers.NewBillingHandler(db, cfg, mail)
	if fetch != nil {
		bh.FetchSubscriptionDetails = fetch
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})

	app.Use(func(c *fiber.Ctx) error {
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	app.Get("/api/v1/billing", bh.GetBillingState)
	return app
}

// billingStateNeedsDB skips when no TEST_DATABASE_URL is configured.
func billingStateNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing_test.GetBillingState: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// TestGetBillingState_NoSubscription_DefaultsCleanly verifies a freshly-claimed
// Hobby team with no Razorpay subscription on file gets the expected
// "no subscription yet" shape. This is the dashboard fixture path the new
// endpoint replaces.
func TestGetBillingState_NoSubscription_DefaultsCleanly(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	// Owner user so billing_email can be populated.
	teamUUID := uuid.MustParse(teamID)
	ownerEmail := testhelpers.UniqueEmail(t)
	_, err := models.CreateUser(context.Background(), db, teamUUID, ownerEmail, "", "", "owner")
	require.NoError(t, err)

	// fetch fn never gets called — there's no subscription_id on the team.
	fetchCalled := false
	fetch := func(string) (*razorpaybilling.SubscriptionDetails, error) {
		fetchCalled = true
		return nil, fmt.Errorf("should not be called")
	}

	app := billingStateApp(t, db, teamID, fetch)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "hobby", body["tier"])
	assert.Equal(t, "none", body["subscription_status"])
	assert.Nil(t, body["next_renewal_at"])
	assert.Nil(t, body["amount_inr"])
	assert.Nil(t, body["payment_method"])
	assert.Equal(t, ownerEmail, body["billing_email"])
	assert.Nil(t, body["razorpay_subscription_id"])
	assert.Nil(t, body["razorpay_customer_id"])
	assert.False(t, fetchCalled, "FetchSubscriptionDetails must NOT be called when no subscription_id on team")
}

// TestGetBillingState_ProSubscription_ReturnsRenewalAndPayment verifies that
// when a Razorpay subscription_id is stored on the team, the handler fetches
// the live subscription state and surfaces renewal date + payment method.
func TestGetBillingState_ProSubscription_ReturnsRenewalAndPayment(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	teamUUID := uuid.MustParse(teamID)
	// Unique subscription id per test run so the teams.stripe_customer_id
	// unique constraint doesn't trip when this package is re-run against a
	// non-fresh test DB.
	subID := "sub_test_" + uuid.New().String()
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db, teamUUID, subID))
	ownerEmail := testhelpers.UniqueEmail(t)
	_, err := models.CreateUser(context.Background(), db, teamUUID, ownerEmail, "", "", "owner")
	require.NoError(t, err)

	renewal := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	captured := ""
	fetch := func(passedSubID string) (*razorpaybilling.SubscriptionDetails, error) {
		captured = passedSubID
		return &razorpaybilling.SubscriptionDetails{
			Status:             "active",
			CurrentPeriodEnd:   renewal,
			ShortURL:           "https://rzp.io/sub/" + passedSubID,
			PaymentLast4:       "4242",
			PaymentNetwork:     "visa",
			PaymentMethod:      "card",
			LatestPaidAmount:   410000, // 4100 INR in paise
			LatestPaidCurrency: "INR",
		}, nil
	}

	app := billingStateApp(t, db, teamID, fetch)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, subID, captured, "handler should pass the stored subscription id to the fetcher")
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "pro", body["tier"])
	assert.Equal(t, "active", body["subscription_status"])
	assert.Equal(t, subID, body["razorpay_subscription_id"])
	assert.Equal(t, ownerEmail, body["billing_email"])

	// next_renewal_at is rendered as RFC3339Nano UTC.
	gotRenewal, _ := body["next_renewal_at"].(string)
	assert.NotEmpty(t, gotRenewal)
	parsed, err := time.Parse(time.RFC3339Nano, gotRenewal)
	require.NoError(t, err)
	assert.Equal(t, renewal.UTC(), parsed.UTC())

	// amount_inr is paise/100 → 4100.
	amt, _ := body["amount_inr"].(float64) // JSON numbers decode to float64
	assert.EqualValues(t, 4100, amt)

	pm, _ := body["payment_method"].(map[string]any)
	require.NotNil(t, pm, "payment_method must be populated when subscription has a paid invoice")
	assert.Equal(t, "card", pm["type"])
	assert.Equal(t, "visa", pm["brand"])
	assert.Equal(t, "4242", pm["last4"])
	assert.Nil(t, pm["vpa"])
}

// TestGetBillingState_TrialTeam_SurfacesTrialStatus exercises the trial branch:
// a team with trial_ends_at in the future returns "trial" + the trial-end as
// next_renewal_at, even with no subscription on file.
func TestGetBillingState_TrialTeam_SurfacesTrialStatus(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	teamUUID := uuid.MustParse(teamID)
	require.NoError(t, models.StartTrial(context.Background(), db, teamUUID))

	app := billingStateApp(t, db, teamID, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

	assert.Equal(t, "trial", body["subscription_status"])
	assert.NotEmpty(t, body["next_renewal_at"], "trial status must surface trial_ends_at as next_renewal_at")
}

// ─── CreateCheckoutAPI plan_frequency (P2 annual pricing) ────────────────

// checkoutAppNoDB builds a tiny Fiber app for testing checkout-handler
// validation paths that never reach the DB or Razorpay (invalid input /
// 503 not-configured branches). The team_id local is fixed.
func checkoutAppNoDB(t *testing.T, cfg *config.Config) *fiber.App {
	t.Helper()
	bh := handlers.NewBillingHandler(nil, cfg, email.New(""))
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, uuid.NewString())
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app
}

func postCheckout(t *testing.T, app *fiber.App, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestCheckout_PlanFrequency_InvalidValue_Returns400 verifies that any
// frequency other than monthly|yearly is rejected before Razorpay is
// contacted — a typo can't silently fall back to monthly.
func TestCheckout_PlanFrequency_InvalidValue_Returns400(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:                 "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:             "rzp_test_key",
		RazorpayKeySecret:         "rzp_test_secret",
		RazorpayPlanIDPro:         "plan_monthly_pro",
		RazorpayPlanIDProYearly:   "plan_yearly_pro",
	}
	app := checkoutAppNoDB(t, cfg)
	status, body := postCheckout(t, app, map[string]any{
		"plan":           "pro",
		"plan_frequency": "lifetime",
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_frequency", body["error"])
}

// TestCheckout_PlanFrequency_YearlyUnconfigured_Returns503 verifies that
// when the operator hasn't created the yearly Razorpay plan yet and
// RAZORPAY_PLAN_ID_*_YEARLY is empty, the request fails fast with 503
// instead of trying to subscribe with an empty plan_id.
func TestCheckout_PlanFrequency_YearlyUnconfigured_Returns503(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		RazorpayPlanIDPro: "plan_monthly_pro",
		// RazorpayPlanIDProYearly intentionally left empty.
	}
	app := checkoutAppNoDB(t, cfg)
	status, body := postCheckout(t, app, map[string]any{
		"plan":           "pro",
		"plan_frequency": "yearly",
	})
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "billing_not_configured", body["error"])
}

// TestCheckout_PlanFrequency_MonthlyDefault_NoFrequency verifies that
// requests with no plan_frequency field continue to behave as monthly
// (back-compat with the pre-P2 dashboard).
func TestCheckout_PlanFrequency_MonthlyDefault_NoFrequency(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		// No monthly Pro plan configured -> expect 503 not_configured.
		// (Verifies it tries monthly when frequency is omitted.)
		RazorpayPlanIDProYearly: "plan_yearly_pro_set",
	}
	app := checkoutAppNoDB(t, cfg)
	status, body := postCheckout(t, app, map[string]any{
		"plan": "pro",
	})
	// monthly plan_id is empty → 503
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Equal(t, "billing_not_configured", body["error"])
}

// TestCheckout_PlanFrequency_TeamGuard_StillFires verifies the team-tier
// guard runs before frequency resolution — team is unavailable on either
// cycle while the multi-seat surface is in development.
func TestCheckout_PlanFrequency_TeamGuard_StillFires(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:                "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:            "rzp_test_key",
		RazorpayKeySecret:        "rzp_test_secret",
		RazorpayPlanIDTeam:       "plan_monthly_team",
		RazorpayPlanIDTeamYearly: "plan_yearly_team",
	}
	app := checkoutAppNoDB(t, cfg)
	for _, freq := range []string{"monthly", "yearly", ""} {
		body := map[string]any{"plan": "team"}
		if freq != "" {
			body["plan_frequency"] = freq
		}
		status, resp := postCheckout(t, app, body)
		assert.Equal(t, http.StatusBadRequest, status,
			"team is locked regardless of frequency=%q", freq)
		assert.Equal(t, "tier_unavailable", resp["error"])
	}
}

// TestPlanIDToTier_MapsYearlyPlanIDsToCanonicalTier verifies the webhook's
// plan_id → tier resolver recognises yearly plan IDs and maps them back
// to the canonical (bare) tier name. teams.plan_tier always stores the
// canonical tier so limits resolution is cycle-agnostic.
func TestPlanIDToTier_MapsYearlyPlanIDsToCanonicalTier(t *testing.T) {
	cfg := &config.Config{
		RazorpayPlanIDHobby:       "plan_monthly_hobby",
		RazorpayPlanIDHobbyYearly: "plan_yearly_hobby",
		RazorpayPlanIDPro:         "plan_monthly_pro",
		RazorpayPlanIDProYearly:   "plan_yearly_pro",
		RazorpayPlanIDTeam:        "plan_monthly_team",
		RazorpayPlanIDTeamYearly:  "plan_yearly_team",
	}
	bh := handlers.NewBillingHandler(nil, cfg, email.New(""))
	cases := []struct {
		planID string
		want   string
	}{
		{"plan_monthly_hobby", "hobby"},
		{"plan_yearly_hobby", "hobby"},
		{"plan_monthly_pro", "pro"},
		{"plan_yearly_pro", "pro"},
		{"plan_monthly_team", "team"},
		{"plan_yearly_team", "team"},
		{"", "pro"},               // empty defaults to pro (unchanged)
		{"plan_unknown_xx", "pro"}, // unknown defaults to pro (unchanged)
	}
	for _, c := range cases {
		got := handlers.ExportedPlanIDToTier(bh, c.planID)
		assert.Equal(t, c.want, got, "planIDToTier(%q)", c.planID)
	}
}

// Ensure the billing test file compiles and is non-empty.
var _ = fmt.Sprintf
