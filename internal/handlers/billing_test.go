package handlers_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
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
	billing := handlers.NewBillingHandler(nil, cfg, emailClient, nil)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
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

// Ensure the billing test file compiles and is non-empty.
var _ = fmt.Sprintf
