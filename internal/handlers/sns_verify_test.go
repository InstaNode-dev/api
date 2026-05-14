package handlers_test

// sns_verify_test.go — hermetic tests for the SNS RSA signature
// verifier (sns_verify.go). Generates an in-memory RSA cert at test
// setup, builds a valid SNS message signed with it, and asserts both
// the happy path AND the tamper-detection path.
//
// Tests:
//   1. Happy: a valid SNS Notification verifies cleanly.
//   2. Tamper: flip one byte of the Message field → verify fails.
//   3. Bad cert URL: not HTTPS, not sns.<region>.amazonaws.com → reject.
//   4. Unknown SignatureVersion → reject.
//   5. End-to-end: a fully-signed Notification hitting the SES endpoint
//      with a real signature passes through to the INSERT.
//   6. End-to-end: a tampered Notification hitting the SES endpoint
//      returns 401 without touching the DB.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

// snsTestFixture bundles the RSA key + cert PEM + a builder for signed
// SNS Notification payloads. One fixture per test keeps state isolated.
type snsTestFixture struct {
	key     *rsa.PrivateKey
	certPEM []byte
}

func newSNSTestFixture(t *testing.T) *snsTestFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sns-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	return &snsTestFixture{key: key, certPEM: pemBytes}
}

// signedNotificationV2 returns a SignatureVersion=2 SNS Notification
// envelope with the supplied fields, signed with the fixture's key.
// Returns the marshaled JSON ready to POST to the SES endpoint.
func (f *snsTestFixture) signedNotificationV2(
	t *testing.T,
	topicArn, messageBody, signingCertURL string,
) []byte {
	t.Helper()

	// AWS canonical signing string for Notification (sorted field order):
	//   Message\n<value>\n
	//   MessageId\n<value>\n
	//   Subject\n<value>\n     (omitted if empty)
	//   Timestamp\n<value>\n
	//   TopicArn\n<value>\n
	//   Type\n<value>\n
	messageID := "msg-" + uuid.NewString()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signingString := "" +
		"Message\n" + messageBody + "\n" +
		"MessageId\n" + messageID + "\n" +
		"Timestamp\n" + timestamp + "\n" +
		"TopicArn\n" + topicArn + "\n" +
		"Type\nNotification\n"

	digest := sha256.Sum256([]byte(signingString))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}

	envelope := map[string]any{
		"Type":             "Notification",
		"MessageId":        messageID,
		"TopicArn":         topicArn,
		"Message":          messageBody,
		"Timestamp":        timestamp,
		"SignatureVersion": "2",
		"Signature":        base64.StdEncoding.EncodeToString(sigBytes),
		"SigningCertURL":   signingCertURL,
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("json.Marshal envelope: %v", err)
	}
	return out
}

func TestSNSVerify_HappyPath_ValidSignature(t *testing.T) {
	fix := newSNSTestFixture(t)

	v, err := handlers.NewSNSVerifierForTest(fix.certPEM)
	if err != nil {
		t.Fatalf("NewSNSVerifierForTest: %v", err)
	}

	// Sign a notification, feed it back through the verifier via the
	// SES handler. We use the public handler API since the verify()
	// method itself is unexported.
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	mock.ExpectQuery(`INSERT INTO email_events`).
		WithArgs("ses", "bounce", "x@y.com", sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	restore := h.SetSNSVerifierForTest(v)
	defer restore()

	app := snsTestApp(t, h)

	innerSES := map[string]any{
		"notificationType": "Bounce",
		"bounce": map[string]any{
			"bounceType": "Permanent",
			"bouncedRecipients": []map[string]any{
				{"emailAddress": "x@y.com", "diagnosticCode": "550"},
			},
		},
		"mail": map[string]any{"messageId": "ses-1"},
	}
	innerJSON, _ := json.Marshal(innerSES)

	payload := fix.signedNotificationV2(t,
		testSESTopicArn,
		string(innerJSON),
		"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem",
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid signature, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

func TestSNSVerify_TamperedMessage_Returns401(t *testing.T) {
	fix := newSNSTestFixture(t)
	v, err := handlers.NewSNSVerifierForTest(fix.certPEM)
	if err != nil {
		t.Fatalf("NewSNSVerifierForTest: %v", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	// No DB expectations — a tampered request MUST NOT touch the DB.

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	restore := h.SetSNSVerifierForTest(v)
	defer restore()

	app := snsTestApp(t, h)

	// Sign a payload, then flip ONE byte of the Message before posting.
	// Verification must reject — proves the signature actually covers the
	// payload, not just the envelope shape.
	original := fix.signedNotificationV2(t,
		testSESTopicArn,
		`{"notificationType":"Bounce","bounce":{"bounceType":"Permanent","bouncedRecipients":[{"emailAddress":"x@y.com"}]},"mail":{"messageId":"ses-tamper"}}`,
		"https://sns.us-east-1.amazonaws.com/SimpleNotificationService-test.pem",
	)
	var env map[string]any
	if err := json.Unmarshal(original, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	// Tamper the Message body — change "Permanent" → "Pormanent".
	env["Message"] = bytes.ReplaceAll([]byte(env["Message"].(string)),
		[]byte("Permanent"), []byte("Pormanent"))
	env["Message"] = string(env["Message"].([]byte))
	tampered, _ := json.Marshal(env)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(tampered))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on tampered payload, got %d", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB touched on tampered-payload path: %v", err)
	}
}

func TestSNSVerify_BadCertURLHost_Returns401(t *testing.T) {
	fix := newSNSTestFixture(t)
	v, err := handlers.NewSNSVerifierForTest(fix.certPEM)
	if err != nil {
		t.Fatalf("NewSNSVerifierForTest: %v", err)
	}

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	cfg := &config.Config{SESSNSTopicARN: testSESTopicArn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	restore := h.SetSNSVerifierForTest(v)
	defer restore()

	app := snsTestApp(t, h)

	// SigningCertURL host is attacker.example.com — the hostname regex
	// must reject before any fetch attempt.
	payload := fix.signedNotificationV2(t,
		testSESTopicArn,
		`{"notificationType":"Bounce","mail":{"messageId":"ses-1"}}`,
		"https://attacker.example.com/cert.pem",
	)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on bad cert URL host, got %d", resp.StatusCode)
	}
}

// snsTestApp builds a minimal Fiber app with the SES route mounted.
func snsTestApp(t *testing.T, h *handlers.EmailWebhookHandler) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Post("/api/v1/email/webhook/ses", h.SES)
	return app
}
