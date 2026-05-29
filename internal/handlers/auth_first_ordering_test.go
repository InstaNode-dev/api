package handlers_test

// auth_first_ordering_test.go — API-19/26/27/28/77/78/96/97/98 (QA 2026-05-29).
//
// Asserts that the webhook + /internal/* auth check runs BEFORE any body
// or path-param validation. The pre-fix posture inverted fail-closed: a
// probe could distinguish "secret unset" / "secret wrong" from "path
// malformed" / "body malformed" by the 401 vs 400 envelope. These tests
// lock in the auth-first ordering and the new explicit error codes:
//
//   webhook_secret_mismatch       — provider secret env var unset
//   webhook_signature_mismatch    — secret IS configured, body sig bad
//   webhook_method_not_allowed    — GET on a POST-only webhook URL
//   internal_token_required       — /internal/* unauth
//
// Hermetic: no DB needed. We construct each handler with nil or sqlmock
// DB and exercise it through a minimal Fiber app.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

// fiberAppWithErrorHandler builds a minimal Fiber app whose ErrorHandler
// translates handlers.ErrResponseWritten back to "no-op" — every test in
// this file relies on respondError having already written the envelope.
func fiberAppWithErrorHandler() *fiber.App {
	return fiber.New(fiber.Config{
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
}

// decodeEnvelope reads the response body into a generic map for code
// assertions. Returns a non-nil map even on parse error so callers can
// keep their assertions terse.
func decodeEnvelope(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// ── Brevo HMAC webhook ───────────────────────────────────────────────────────

// TestBrevoWebhook_SecretUnset_Returns401_WithWebhookSecretMismatch covers
// API-19/96. Pre-fix the route returned 401 invalid_signature; post-fix
// the SECRET-unset branch must return 401 webhook_secret_mismatch so an
// operator alert can target the deploy-the-secret incident specifically.
func TestBrevoWebhook_SecretUnset_Returns401_WithWebhookSecretMismatch(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{BrevoWebhookSecret: ""}
	h := handlers.NewEmailWebhookHandler(db, cfg)

	app := fiberAppWithErrorHandler()
	app.Post("/api/v1/email/webhook/brevo", h.Brevo)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo",
		bytes.NewReader([]byte(`{"event":"hard_bounce"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "webhook_secret_mismatch", env["error"])
}

// TestBrevoWebhook_SignatureMismatch_Returns401_WithWebhookSignatureMismatch
// covers the secret-set-but-sig-bad branch. Distinct error code so observability
// can split "secret unset" from "signature mismatch" (provider rotated key /
// drive-by attacker).
func TestBrevoWebhook_SignatureMismatch_Returns401_WithWebhookSignatureMismatch(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{BrevoWebhookSecret: "test-secret-32-bytes-padded-xxxx"}
	h := handlers.NewEmailWebhookHandler(db, cfg)

	app := fiberAppWithErrorHandler()
	app.Post("/api/v1/email/webhook/brevo", h.Brevo)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/brevo",
		bytes.NewReader([]byte(`{"event":"hard_bounce","email":"x@y.test"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sib-Signature", "deadbeef-not-a-real-sig")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "webhook_signature_mismatch", env["error"])
}

// TestBrevoWebhook_GetReturns405_WithWebhookMethodNotAllowed covers API-98:
// dashboard pre-flight GET on the webhook URL must see 405 + Allow: POST
// rather than the catch-all 401, so the dashboard interprets the URL as
// valid-but-method-wrong instead of unauthenticated-abandon.
func TestBrevoWebhook_GetReturns405_WithWebhookMethodNotAllowed(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{}
	h := handlers.NewEmailWebhookHandler(db, cfg)

	app := fiberAppWithErrorHandler()
	app.Get("/api/v1/email/webhook/brevo", h.BrevoMethodNotAllowed)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/email/webhook/brevo", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	require.Equal(t, "POST", resp.Header.Get("Allow"))
	env := decodeEnvelope(t, resp)
	require.Equal(t, "webhook_method_not_allowed", env["error"])
}

// ── SES/SNS webhook ──────────────────────────────────────────────────────────

// TestSESWebhook_SecretUnset_Returns401_BeforeBodyParse covers API-97:
// the secret-unset (SES_SNS_SUBSCRIPTION_ARN empty) check must fire before
// envelope parsing. A junk body MUST return 401 webhook_secret_mismatch
// (not 400 invalid_payload) so a probe can't distinguish the two by
// manipulating the payload.
func TestSESWebhook_SecretUnset_Returns401_BeforeBodyParse(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{SESSNSTopicARN: ""}
	h := handlers.NewEmailWebhookHandler(db, cfg)

	app := fiberAppWithErrorHandler()
	app.Post("/api/v1/email/webhook/ses", h.SES)

	// Junk body — would 400 invalid_payload pre-fix because envelope parse
	// ran before the secret check. Post-fix the secret-unset branch wins.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses",
		bytes.NewReader([]byte(`THIS IS NOT JSON AT ALL`)))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "webhook_secret_mismatch", env["error"])
}

// TestSESWebhook_BadSignature_Returns401_WithWebhookSignatureMismatch:
// secret IS configured, but the inbound envelope's TopicArn does not match.
// Distinct from the SECRET-unset path above.
func TestSESWebhook_BadSignature_Returns401_WithWebhookSignatureMismatch(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	cfg := &config.Config{SESSNSTopicARN: "arn:aws:sns:us-east-1:123456789012:bounces"}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	h.DisableSNSVerifierForTest()

	app := fiberAppWithErrorHandler()
	app.Post("/api/v1/email/webhook/ses", h.SES)

	body := []byte(`{"Type":"Notification","TopicArn":"arn:aws:sns:us-east-1:999:wrong","Message":"{}"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "webhook_signature_mismatch", env["error"])
}

// TestSESWebhook_GoodTopicArn_Returns200_NotSuppressionWorthy: the
// auth-passed path still works. A SubscriptionConfirmation envelope with
// the right TopicArn returns 200 (subscription_pending=true) — verifies we
// didn't accidentally 401 a real provider payload.
func TestSESWebhook_GoodTopicArn_Returns200_NotSuppressionWorthy(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	arn := "arn:aws:sns:us-east-1:123456789012:bounces"
	cfg := &config.Config{SESSNSTopicARN: arn}
	h := handlers.NewEmailWebhookHandler(db, cfg)
	h.DisableSNSVerifierForTest()

	app := fiberAppWithErrorHandler()
	app.Post("/api/v1/email/webhook/ses", h.SES)

	body := []byte(`{"Type":"SubscriptionConfirmation","TopicArn":"` + arn + `","SubscribeURL":"https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription","Message":"{}"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/email/webhook/ses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, true, env["ok"])
}

// ── Internal endpoints — auth-first ordering ─────────────────────────────────

// newInternalTerminateApp builds a minimal app wired only to the
// terminate handler with the supplied secret. cancelFn is nil so the
// handler short-circuits the Razorpay step.
func newInternalTerminateApp(secret string) *fiber.App {
	db, _, _ := sqlmock.New()
	cfg := &config.Config{WorkerInternalJWTSecret: secret}
	h := handlers.NewInternalTerminateHandler(db, cfg, nil)
	app := fiberAppWithErrorHandler()
	app.Post("/internal/teams/:id/terminate", h.Terminate)
	return app
}

// TestInternalTerminate_AuthCheckBeforePathParse covers API-26/77:
// posting a bogus token to a path with a malformed :id must return 401
// internal_token_required (not 400 invalid_team_id). Pre-fix the path
// parse ran first and surfaced 400 — leaking the route's shape.
func TestInternalTerminate_AuthCheckBeforePathParse(t *testing.T) {
	app := newInternalTerminateApp("worker-internal-secret-32-bytes!")

	// Malformed path :id (not a UUID) + bogus bearer.
	req := httptest.NewRequest(http.MethodPost, "/internal/teams/NOT-A-UUID/terminate", nil)
	req.Header.Set("Authorization", "Bearer junk-token-not-a-real-jwt")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "auth must fire BEFORE path parse")
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}

// TestInternalTerminate_SecretUnset_RejectsAllRegardlessOfPath: when the
// worker secret env var is unset, EVERY call 401s — even with a malformed
// path. The pre-fix path-parse-first ordering would have surfaced 400 on
// a junk path, telling the probe "this would have been a real endpoint if
// only you sent a valid path".
func TestInternalTerminate_SecretUnset_RejectsAllRegardlessOfPath(t *testing.T) {
	app := newInternalTerminateApp("")

	req := httptest.NewRequest(http.MethodPost, "/internal/teams/NOT-A-UUID/terminate", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}

// newInternalResendApp wires the resend handler with the supplied secret.
// The mailer is nil — auth-fail paths return before any send is attempted.
func newInternalResendApp(secret string) *fiber.App {
	db, _, _ := sqlmock.New()
	cfg := &config.Config{WorkerInternalJWTSecret: secret}
	// nil mailer is fine — the auth-fail path returns before the mailer
	// is touched.
	h := handlers.NewInternalResendMagicLinkHandler(db, cfg, nil)
	app := fiberAppWithErrorHandler()
	app.Post("/internal/email/resend-magic-link", h.Resend)
	return app
}

// TestInternalResendMagicLink_AuthCheckBeforeBodyParse covers API-27/78:
// a malformed body with a bogus bearer must return 401 internal_token_required
// (not 400 invalid_body). Pre-fix body parse ran first.
func TestInternalResendMagicLink_AuthCheckBeforeBodyParse(t *testing.T) {
	app := newInternalResendApp("worker-internal-secret-32-bytes!")

	// Malformed body + bogus bearer.
	req := httptest.NewRequest(http.MethodPost, "/internal/email/resend-magic-link",
		bytes.NewReader([]byte(`THIS IS NOT JSON`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer junk-token-not-a-real-jwt")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "auth must fire BEFORE body parse")
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}

// TestInternalResendMagicLink_SecretUnset_RejectsRegardlessOfBody: secret
// unset → 401 internal_token_required even with junk body.
func TestInternalResendMagicLink_SecretUnset_RejectsRegardlessOfBody(t *testing.T) {
	app := newInternalResendApp("")

	req := httptest.NewRequest(http.MethodPost, "/internal/email/resend-magic-link",
		bytes.NewReader([]byte(`JUNK`)))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}

// newInternalRefundApp wires the refund handler with the supplied secret.
// rdb is nil — the auth-fail path returns before Redis is touched.
func newInternalRefundApp(secret string) *fiber.App {
	db, _, _ := sqlmock.New()
	cfg := &config.Config{WorkerInternalJWTSecret: secret}
	h := handlers.NewInternalBackupRefundHandler(db, nil, cfg)
	app := fiberAppWithErrorHandler()
	app.Post("/internal/teams/:id/backup-quota/refund", h.Refund)
	return app
}

// TestInternalRefund_AuthCheckBeforePathParse covers API-28: a malformed
// :id with a bogus bearer must return 401 internal_token_required
// (not 400 invalid_team_id).
func TestInternalRefund_AuthCheckBeforePathParse(t *testing.T) {
	app := newInternalRefundApp("worker-internal-secret-32-bytes!")

	req := httptest.NewRequest(http.MethodPost, "/internal/teams/NOT-A-UUID/backup-quota/refund",
		bytes.NewReader([]byte(`{"backup_id":"junk"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer junk-token-not-a-real-jwt")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "auth must fire BEFORE path parse")
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}

// TestInternalRefund_SecretUnset_RejectsRegardlessOfPath: secret unset →
// 401 internal_token_required even with junk path.
func TestInternalRefund_SecretUnset_RejectsRegardlessOfPath(t *testing.T) {
	app := newInternalRefundApp("")

	req := httptest.NewRequest(http.MethodPost, "/internal/teams/NOT-A-UUID/backup-quota/refund",
		bytes.NewReader([]byte(`{}`)))
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	env := decodeEnvelope(t, resp)
	require.Equal(t, "internal_token_required", env["error"])
}
