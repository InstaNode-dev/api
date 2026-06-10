package handlers_test

// billing_webhook_sig_fail_metric_test.go — S4 (metric half, 2026-06-10).
//
// A forged-signature POST /razorpay/webhook must bump
// instant_razorpay_webhook_sig_fail_total (mirroring the GitHub webhook
// bad-signature counter) so an operator can chart "N signature failures / hour"
// without grepping the billing.webhook.signature_failed slog line. Pre-fix the
// only signal was the log line + a best-effort audit row.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/metrics"
	"instant.dev/internal/middleware"
)

// TestRazorpayWebhook_ForgedSignature_IncrementsSigFailCounter posts a body with
// a deliberately wrong X-Razorpay-Signature and asserts the sig-fail counter
// rises by exactly one and the response is a 4xx (Razorpay's retry contract is
// covered elsewhere; here we pin the metric). db is nil so the best-effort
// audit-row block no-ops — the counter increment is independent of it.
func TestRazorpayWebhook_ForgedSignature_IncrementsSigFailCounter(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: "live_webhook_secret_for_this_test_only_xxxxxx",
	}
	billing := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	before := testutil.ToFloat64(metrics.RazorpayWebhookSigFail)

	payload := []byte(`{"event":"subscription.charged","payload":{}}`)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// A signature that cannot verify against the configured secret.
	req.Header.Set("X-Razorpay-Signature", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.GreaterOrEqual(t, resp.StatusCode, 400,
		"a forged-signature webhook must be rejected with a 4xx")

	after := testutil.ToFloat64(metrics.RazorpayWebhookSigFail)
	assert.Equal(t, before+1, after,
		"instant_razorpay_webhook_sig_fail_total must increment by exactly 1 on a signature failure (S4)")
}
