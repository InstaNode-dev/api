package handlers_test

// email_webhooks_test.go — hermetic tests for the Brevo + SES webhook
// endpoints. We exercise:
//
//   1. Brevo bounce with a valid signature → 200 + INSERT fired.
//   2. Brevo with a bad signature → 401 (NOT 400, and NOT 200).
//   3. SES SNS Notification with matching TopicArn → INSERT fired with
//      the SES messageId surfaced under raw->>'message_id'.
//   4. SES with wrong TopicArn → 401.
//   5. SES SubscriptionConfirmation → 200, no INSERT.
//   6. Brevo "opened" event (not suppression-worthy) → 200, no INSERT.
//
// All tests use sqlmock for the DB so they run with no infra. The
// webhook handler is constructed directly; only the routes-under-test
// are mounted on the Fiber app — no auth middleware in front because
// the handlers self-authenticate.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

const (
	testBrevoSecret  = "test_brevo_webhook_secret_at_least_32_bytes"
	testSESTopicArn  = "arn:aws:sns:us-east-1:123456789012:instant-email-feedback"
)

// emailWebhookApp builds a minimal Fiber app with just the two email
// webhook routes mounted. db comes in via parameter so each test can
// drive its own sqlmock expectations.
func emailWebhookApp(t *testing.T, h *handlers.EmailWebhookHandler) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Post("/api/v1/email/webhook/brevo", h.Brevo)
	app.Post("/api/v1/email/webhook/ses", h.SES)
	return app
}

// signBrevo returns hex(HMAC-SHA256(key=secret, msg=payload)).
func signBrevo(t *testing.T, secret string, payload []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// ── Brevo tests ──────────────────────────────────────────────────────────────

func TestEmailWebhook_Brevo_HardBounce_InsertsRow(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`INSERT INTO email_events`).
		WithArgs("brevo", "bounce", "bouncey@example.com", "Mailbox does not exist", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"hard_bounce","email":"bouncey@example.com","reason":"Mailbox does not exist","message-id":"<brevo-msg-1@example.com>"}`)
	sig := signBrevo(t, testBrevoSecret, payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", sig)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations not met: %v", err)
	}
}

func TestEmailWebhook_Brevo_BadSignature_Returns401(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No DB expectations — a bad-sig request MUST NOT touch the DB.

	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"hard_bounce","email":"bouncey@example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", "deadbeef-not-a-valid-signature")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB was touched on bad-sig path: %v", err)
	}
}

func TestEmailWebhook_Brevo_LegacyHeader_Accepted(t *testing.T) {
	// Brevo's older docs called the header X-Mailin-Custom. Verify the
	// handler still accepts that name. Confirms the dual-header fallback
	// in email_webhooks.go.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`INSERT INTO email_events`).
		WithArgs("brevo", "unsubscribe", "leaver@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"unsubscribed","email":"leaver@example.com","message-id":"<legacy-1@example.com>"}`)
	sig := signBrevo(t, testBrevoSecret, payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Mailin-Custom", sig) // legacy header

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with legacy header, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestEmailWebhook_Brevo_OpenedEvent_SkippedNoInsert(t *testing.T) {
	// Brevo fires opens/clicks/delivered events; we only care about
	// suppression-worthy ones. Verify a non-suppression event returns
	// 200 WITHOUT touching the DB.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No expectations — opened MUST NOT INSERT.

	cfg := &config.Config{BrevoWebhookSecret: testBrevoSecret}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"opened","email":"reader@example.com"}`)
	sig := signBrevo(t, testBrevoSecret, payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", sig)

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for opened-event skip, got %d", resp.StatusCode)
	}
	body, _ := readJSONBody(resp)
	if skipped, _ := body["skipped"].(bool); !skipped {
		t.Errorf("expected skipped=true for opened event, got body=%v", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB touched on opened-event path: %v", err)
	}
}

func TestEmailWebhook_Brevo_MissingSecret_AllRequestsRejected(t *testing.T) {
	// Fail-closed: empty secret → every request 401, even one with no
	// signature header. Confirms verifyBrevoSignature's empty-secret guard.
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{BrevoWebhookSecret: ""} // not configured
	h := handlers.NewEmailWebhookHandler(db, cfg)
	app := emailWebhookApp(t, h)

	payload := []byte(`{"event":"hard_bounce","email":"x@y.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with unset secret, got %d", resp.StatusCode)
	}
}

// ── SES tests ────────────────────────────────────────────────────────────────

// buildSESEnvelope returns the SNS envelope JSON for a SES Bounce
// notification with the given recipient address.
func buildSESEnvelope(t *testing.T, topicArn, notificationType, recipient string) []byte {
	t.Helper()
	var sesMsg map[string]any
	switch notificationType {
	case "Bounce":
		sesMsg = map[string]any{
			"notificationType": "Bounce",
			"bounce": map[string]any{
				"bounceType": "Permanent",
				"bouncedRecipients": []map[string]any{
					{"emailAddress": recipient, "diagnosticCode": "smtp; 550 5.1.1 user unknown"},
				},
			},
			"mail": map[string]any{"messageId": "ses-msg-abc-123"},
		}
	case "Complaint":
		sesMsg = map[string]any{
			"notificationType": "Complaint",
			"complaint": map[string]any{
				"complainedRecipients": []map[string]any{
					{"emailAddress": recipient},
				},
			},
			"mail": map[string]any{"messageId": "ses-msg-xyz-456"},
		}
	default:
		t.Fatalf("buildSESEnvelope: unsupported notificationType %q", notificationType)
	}
	msgBytes, _ := json.Marshal(sesMsg)
	envelope := map[string]any{
		"Type":     "Notification",
		"TopicArn": topicArn,
		"Message":  string(msgBytes),
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("buildSESEnvelope marshal: %v", err)
	}
	return out
}

func TestEmailWebhook_SES_PermanentBounce_InsertsRow(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`INSERT INTO email_events`).
		WithArgs("ses", "bounce", "ses-bounce@example.com", "smtp; 550 5.1.1 user unknown", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	// Legacy fixtures don't include a valid SNS RSA signature; disable
	// verification here so these tests keep asserting the TopicArn /
	// notificationType branches. The full RSA signature path has its
	// own dedicated tests in sns_verify_test.go.
	h.DisableSNSVerifierForTest()
	app := emailWebhookApp(t, h)

	payload := buildSESEnvelope(t, testSESTopicArn, "Bounce", "ses-bounce@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestEmailWebhook_SES_Complaint_InsertsAsSpamComplaint(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`INSERT INTO email_events`).
		WithArgs("ses", "spam_complaint", "angry@example.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	// Legacy fixtures don't include a valid SNS RSA signature; disable
	// verification here so these tests keep asserting the TopicArn /
	// notificationType branches. The full RSA signature path has its
	// own dedicated tests in sns_verify_test.go.
	h.DisableSNSVerifierForTest()
	app := emailWebhookApp(t, h)

	payload := buildSESEnvelope(t, testSESTopicArn, "Complaint", "angry@example.com")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestEmailWebhook_SES_WrongTopicArn_Returns401(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No DB expectations — a bad-ARN request MUST NOT touch the DB.

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	// Legacy fixtures don't include a valid SNS RSA signature; disable
	// verification here so these tests keep asserting the TopicArn /
	// notificationType branches. The full RSA signature path has its
	// own dedicated tests in sns_verify_test.go.
	h.DisableSNSVerifierForTest()
	app := emailWebhookApp(t, h)

	payload := buildSESEnvelope(t, "arn:aws:sns:us-east-1:000:attacker", "Bounce", "x@x.com")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong TopicArn, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB touched on bad-ARN path: %v", err)
	}
}

func TestEmailWebhook_SES_SubscriptionConfirmation_NoInsert(t *testing.T) {
	// One-time SNS subscription confirmation — return 200 without
	// inserting anything. Operator confirms out-of-band via AWS console.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	// Legacy fixtures don't include a valid SNS RSA signature; disable
	// verification here so these tests keep asserting the TopicArn /
	// notificationType branches. The full RSA signature path has its
	// own dedicated tests in sns_verify_test.go.
	h.DisableSNSVerifierForTest()
	app := emailWebhookApp(t, h)

	payload, _ := json.Marshal(map[string]any{
		"Type":         "SubscriptionConfirmation",
		"TopicArn":     testSESTopicArn,
		"SubscribeURL": "https://sns.amazonaws.com/?confirm-here",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for SubscriptionConfirmation, got %d", resp.StatusCode)
	}
	body, _ := readJSONBody(resp)
	if pending, _ := body["subscription_pending"].(bool); !pending {
		t.Errorf("expected subscription_pending=true, got %v", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB touched on SubscriptionConfirmation: %v", err)
	}
}

func TestEmailWebhook_SES_DeliveryNotification_SkippedNoInsert(t *testing.T) {
	// SES fires "Delivery" notifications which are NOT suppression-worthy.
	// Confirm we don't accidentally treat them as bounces.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	// Legacy fixtures don't include a valid SNS RSA signature; disable
	// verification here so these tests keep asserting the TopicArn /
	// notificationType branches. The full RSA signature path has its
	// own dedicated tests in sns_verify_test.go.
	h.DisableSNSVerifierForTest()
	app := emailWebhookApp(t, h)

	inner, _ := json.Marshal(map[string]any{
		"notificationType": "Delivery",
		"mail":             map[string]any{"messageId": "ses-msg-delivery-1"},
	})
	envelope, _ := json.Marshal(map[string]any{
		"Type":     "Notification",
		"TopicArn": testSESTopicArn,
		"Message":  string(inner),
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(envelope))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for Delivery skip, got %d", resp.StatusCode)
	}
	body, _ := readJSONBody(resp)
	if skipped, _ := body["skipped"].(bool); !skipped {
		t.Errorf("expected skipped=true for Delivery, got %v", body)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB touched on Delivery: %v", err)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func readJSONBody(resp *http.Response) (map[string]any, error) {
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}
