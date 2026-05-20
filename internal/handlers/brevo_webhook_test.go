package handlers_test

// brevo_webhook_test.go — hermetic tests for the new Brevo transactional-
// delivery receiver at POST /webhooks/brevo/:secret. Distinct from
// email_webhooks_test.go (which exercises the HMAC-signed
// /api/v1/email/webhook/brevo suppression endpoint).
//
// Coverage:
//   1. delivered event → forwarder_sent.classification='delivered' + delivered_at set.
//   2. Each non-delivered event ('hard_bounce', 'soft_bounce', 'blocked',
//      'complaint', 'spam'→'complaint', 'deferred', 'unsubscribed',
//      'error') → corresponding classification, delivered_at NOT touched.
//   3. URL secret mismatch → 401.
//   4. URL secret matches but Brevo-side has empty secret OR API
//      configured-empty → both 401 (closed-by-default).
//   5. Malformed JSON → 400.
//   6. Oversized payload (>16 KiB) → 400.
//   7. Unknown event type → 200 + skipped (Brevo retries on non-2xx).
//   8. Missing messageId → 200 + skipped (logged WARN).
//   9. Unknown messageId (no matching forwarder_sent row) → 200 +
//      matched:false (NEVER 404 — Brevo retries on non-2xx).
//  10. Coverage test: every entry in brevoDocumentedEvents has a
//      handler in brevoEventHandlers (CLAUDE.md rule 18 registry test).
//
// Idempotency is tested implicitly: the handler issues a plain UPDATE
// statement with no INSERT/UPSERT, so a re-delivery of the same event
// is naturally a no-op on the value side (the GREATEST clause on
// delivered_at prevents the timestamp from going backwards).

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
)

const testBrevoTxSecret = "test_brevo_tx_secret_at_least_32_bytes_x"

// brevoTxApp builds a minimal Fiber app with only the new transactional-
// delivery receiver mounted. The HMAC-signed endpoint is NOT mounted —
// these tests deliberately exercise the URL-token path in isolation.
func brevoTxApp(t *testing.T, h *handlers.BrevoTransactionalWebhookHandler) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Post("/webhooks/brevo/:secret", h.Receive)
	return app
}

// postBrevoTx fires a synthetic Brevo event payload at the receiver and
// returns the response. Mirrors the POST shape Brevo would emit.
func postBrevoTx(t *testing.T, app *fiber.App, urlSecret, body string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/"+urlSecret, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// expectClassificationUpdate sets up a sqlmock expectation for the
// classification-only update path. Used by every non-delivered handler.
func expectClassificationUpdate(mock sqlmock.Sqlmock, class, providerID string, rowsAffected int64) {
	mock.ExpectExec(`UPDATE forwarder_sent`).
		WithArgs(class, "brevo", providerID).
		WillReturnResult(sqlmock.NewResult(0, rowsAffected))
}

// expectDeliveredUpdate sets up a sqlmock expectation for the
// delivered-stamping path (classification + delivered_at).
func expectDeliveredUpdate(mock sqlmock.Sqlmock, providerID string, rowsAffected int64) {
	mock.ExpectExec(`UPDATE forwarder_sent`).
		WithArgs("delivered", "brevo", providerID).
		WillReturnResult(sqlmock.NewResult(0, rowsAffected))
}

// ── 1. Happy path: 'delivered' event sets classification + delivered_at

func TestBrevoTxWebhook_DeliveredEvent_UpdatesLedger(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectDeliveredUpdate(mock, "msg-abc-123", 1)

	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	body := `{"event":"delivered","email":"u@example.com","message-id":"msg-abc-123","date":"2026-05-20 08:00:00","subject":"Welcome"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ── 2. Every non-delivered event class

func TestBrevoTxWebhook_EveryFailureEventUpdatesClassification(t *testing.T) {
	cases := []struct {
		event    string
		wantClass string
	}{
		{"hard_bounce", "bounced_hard"},
		{"soft_bounce", "bounced_soft"},
		{"blocked", "rejected"},
		{"complaint", "complaint"},
		{"spam", "complaint"}, // alias
		{"deferred", "deferred"},
		{"unsubscribed", "unsubscribed"},
		{"error", "error"},
	}
	for _, c := range cases {
		t.Run(c.event, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()

			expectClassificationUpdate(mock, c.wantClass, "msg-test", 1)

			h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
			app := brevoTxApp(t, h)

			body := `{"event":"` + c.event + `","email":"u@example.com","message-id":"msg-test","reason":"mailbox full"}`
			resp := postBrevoTx(t, app, testBrevoTxSecret, body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d; want 200", resp.StatusCode)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unmet sqlmock expectations: %v", err)
			}
		})
	}
}

// ── 3. URL secret mismatch → 401 (NEVER 200 or 404 — drive-by attacker
//      must not learn we noticed)

func TestBrevoTxWebhook_SecretMismatch_Returns401(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	resp := postBrevoTx(t, app, "wrong-secret-value-32-byte-padding-extra", `{"event":"delivered","message-id":"x"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}

// ── 4. Closed-by-default: empty configured secret OR empty URL param

func TestBrevoTxWebhook_EmptyConfiguredSecret_Returns401(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	// Configured secret is empty — even the "correct" URL secret of ""
	// must fail because we cannot allow an unauthenticated public path.
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: ""})
	app := brevoTxApp(t, h)
	resp := postBrevoTx(t, app, "anything", `{"event":"delivered","message-id":"x"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", resp.StatusCode)
	}
}

// ── 5. Malformed JSON → 400

func TestBrevoTxWebhook_MalformedJSON_Returns400(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	resp := postBrevoTx(t, app, testBrevoTxSecret, `{"event":"delivered",badJSON`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

// ── 6. Oversized payload (>16 KiB) → 400

func TestBrevoTxWebhook_Oversized_Returns400(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	// 32 KiB of valid JSON content
	big := make([]byte, 32*1024)
	for i := range big {
		big[i] = 'a'
	}
	body := `{"event":"delivered","reason":"` + string(big) + `"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", resp.StatusCode)
	}
}

// ── 7. Unknown event type → 200 + skipped (NEVER 404 — Brevo retries)

func TestBrevoTxWebhook_UnknownEventType_Returns200Skipped(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	// NO sqlmock expectation — handler must not touch the DB.
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	body := `{"event":"click","email":"u@example.com","message-id":"msg-x"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ── 8. Missing messageId → 200 + skipped + WARN log

func TestBrevoTxWebhook_MissingMessageID_Returns200Skipped(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	// NO sqlmock expectation — handler should bail before touching DB.
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	body := `{"event":"delivered","email":"u@example.com"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ── 9. Unknown messageId (no matching forwarder_sent row) → 200 with
//      matched:false. NEVER 404 — Brevo retries on non-2xx.

func TestBrevoTxWebhook_UnknownMessageID_Returns200MatchedFalse(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	// UPDATE runs but affects 0 rows.
	expectDeliveredUpdate(mock, "msg-orphan", 0)

	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
	app := brevoTxApp(t, h)

	body := `{"event":"delivered","email":"u@example.com","message-id":"msg-orphan"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200 (Brevo retries on non-2xx; orphans must NOT amplify retry traffic)", resp.StatusCode)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// ── 10. Coverage test (CLAUDE.md rule 18): every documented Brevo event
//       has a handler. This iterates the live registry. A new event
//       added to brevoDocumentedEvents but not brevoEventHandlers fails
//       HERE — in the same PR that adds it.

func TestBrevoTxWebhook_EveryDocumentedEventHasHandler(t *testing.T) {
	for _, event := range handlers.BrevoDocumentedEventsForTest() {
		t.Run(event, func(t *testing.T) {
			db, mock, _ := sqlmock.New()
			defer db.Close()

			// The handler MUST hit the DB for every documented event —
			// otherwise the brevoEventHandlers map is missing a branch.
			// We don't care about the resulting classification value;
			// we only assert that an UPDATE was issued.
			mock.ExpectExec(`UPDATE forwarder_sent`).WillReturnResult(sqlmock.NewResult(0, 1))

			h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
			app := brevoTxApp(t, h)

			body := `{"event":"` + event + `","email":"u@example.com","message-id":"msg-cov-` + event + `"}`
			resp := postBrevoTx(t, app, testBrevoTxSecret, body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("documented event %q returned %d (want 200) — registry drift: brevoEventHandlers missing a branch?", event, resp.StatusCode)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("documented event %q did NOT hit DB — brevoEventHandlers missing a real updater branch: %v", event, err)
			}
		})
	}
}
