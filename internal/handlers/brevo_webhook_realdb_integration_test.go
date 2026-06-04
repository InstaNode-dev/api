package handlers_test

// brevo_webhook_realdb_integration_test.go — REAL-DB integration coverage for
// the Brevo transactional-delivery receiver at POST /webhooks/brevo/:secret.
//
// WHY THIS FILE EXISTS (integration-coverage wave 2, 2026-06-04):
//
// brevo_webhook_test.go drives the same handler entirely through sqlmock — it
// asserts the handler ISSUES the right SQL string, but it never proves the SQL
// is CORRECT against a real Postgres schema. The rule-12 email truth surface
// (forwarder_sent.classification + delivered_at) is only as trustworthy as the
// actual UPDATE behaviour:
//
//   * the delivered path uses COALESCE(GREATEST(delivered_at, NOW()), NOW())
//     — a sqlmock can't tell us whether that expression even parses against
//     the real column type, let alone that it's monotonic.
//   * the bug-bash #6 terminal-class guard
//     (classification NOT IN (bounced_hard, bounced_soft, rejected, complaint,
//     unsubscribed)) is a row-state predicate — sqlmock returns whatever rows
//     we tell it to; only a real row can prove a late 'delivered' does NOT
//     clobber a recorded 'bounced_hard'.
//
// These tests seed a real forwarder_sent row, POST a synthetic Brevo event
// (the same shape Brevo emits — NOT a live send, so the unvalidated-sender
// production block is irrelevant), and read the row back via the production
// LookupForwarderSentByProviderID helper to assert the ledger overwrite.
//
// Tests are skipped (not failed) when TEST_DATABASE_URL is unreachable so the
// hermetic `-short` gate stays green; CI supplies the DB and runs them for
// real.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// brevoTxRealApp builds a Fiber app with ONLY the transactional-delivery
// receiver mounted, wired to the supplied real *sql.DB. Mirrors the production
// ErrorHandler short-circuit so respondError envelopes pass through unchanged.
func brevoTxRealApp(t *testing.T, db *sql.DB) *fiber.App {
	t.Helper()
	h := handlers.NewBrevoTransactionalWebhookHandler(db, &config.Config{BrevoWebhookSecret: testBrevoTxSecret})
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

// seedForwarderSent inserts a forwarder_sent row with the given provider_id +
// initial classification and returns the audit_id. The row carries
// provider='brevo' so the receiver's (provider, provider_id) lookup matches.
func seedForwarderSent(t *testing.T, db *sql.DB, providerID, classification string) string {
	t.Helper()
	auditID := uuid.NewString()
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO forwarder_sent (audit_id, provider, provider_id, recipient, template_kind, classification)
		VALUES ($1, 'brevo', $2, 'u***@example.com', 'anon.expiry_warning', $3)
	`, auditID, providerID, classification)
	if err != nil {
		t.Fatalf("seedForwarderSent: %v", err)
	}
	return auditID
}

// ── 1. delivered event overwrites classification AND stamps delivered_at ──

func TestBrevoTxWebhook_RealDB_DeliveredOverwritesLedger(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	providerID := "msg-realdb-" + uuid.NewString()[:8]
	seedForwarderSent(t, db, providerID, "success") // worker's API-acceptance state

	app := brevoTxRealApp(t, db)
	body := `{"event":"delivered","email":"u@example.com","message-id":"` + providerID + `","subject":"Welcome"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}

	row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("LookupForwarderSentByProviderID: %v", err)
	}
	if row.Classification != "delivered" {
		t.Errorf("classification = %q; want delivered (rule-12 truth surface must overwrite the worker's 'success')", row.Classification)
	}
	if row.DeliveredAt == nil {
		t.Error("delivered_at must be stamped on a 'delivered' event; got nil")
	}
}

// ── 2. each non-delivered event overwrites classification, leaves delivered_at NULL ──

func TestBrevoTxWebhook_RealDB_FailureEventsOverwriteClassification(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	cases := []struct {
		event     string
		wantClass string
	}{
		{"hard_bounce", "bounced_hard"},
		{"soft_bounce", "bounced_soft"},
		{"blocked", "rejected"},
		{"complaint", "complaint"},
		{"spam", "complaint"}, // alias → complaint
		{"deferred", "deferred"},
		{"unsubscribed", "unsubscribed"},
		{"error", "error"},
	}
	app := brevoTxRealApp(t, db)
	for _, c := range cases {
		t.Run(c.event, func(t *testing.T) {
			providerID := "msg-fail-" + c.event + "-" + uuid.NewString()[:8]
			seedForwarderSent(t, db, providerID, "success")

			body := `{"event":"` + c.event + `","email":"u@example.com","message-id":"` + providerID + `","reason":"mailbox full"}`
			resp := postBrevoTx(t, app, testBrevoTxSecret, body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d; want 200", resp.StatusCode)
			}

			row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if row.Classification != c.wantClass {
				t.Errorf("classification = %q; want %q", row.Classification, c.wantClass)
			}
			// Only the 'delivered' event ever stamps delivered_at.
			if row.DeliveredAt != nil {
				t.Errorf("delivered_at must stay NULL on a %q event; got %v", c.event, row.DeliveredAt)
			}
		})
	}
}

// ── 3. bug-bash #6 terminal-class guard: a LATE 'delivered' must NOT clobber a
//       recorded 'bounced_hard'. This is the #6 guard area the brief calls out
//       — it can ONLY be proven against a real row (sqlmock can't enforce the
//       NOT IN row-state predicate).

func TestBrevoTxWebhook_RealDB_LateDeliveredDoesNotClobberHardBounce(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	providerID := "msg-terminal-" + uuid.NewString()[:8]
	// The row is ALREADY terminal — a hard bounce was recorded first.
	seedForwarderSent(t, db, providerID, "bounced_hard")

	app := brevoTxRealApp(t, db)
	// Out-of-order: Brevo's SMTP-accept 'delivered' arrives AFTER the bounce.
	body := `{"event":"delivered","email":"u@example.com","message-id":"` + providerID + `"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200", resp.StatusCode)
	}

	row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if row.Classification != "bounced_hard" {
		t.Errorf("terminal class clobbered: classification = %q; want bounced_hard preserved (bug-bash #6)", row.Classification)
	}
	if row.DeliveredAt != nil {
		t.Errorf("delivered_at must NOT be stamped when the terminal class is preserved; got %v", row.DeliveredAt)
	}
}

// ── 3b. the guard also preserves the OTHER terminal classes, and a 'delivered'
//        DOES win when the prior state is a non-terminal 'deferred'. This pins
//        the exact NOT IN set so a future edit that drops a class from the
//        guard fails here.

func TestBrevoTxWebhook_RealDB_TerminalGuardSetIsExact(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := brevoTxRealApp(t, db)

	cases := []struct {
		name           string
		seedClass      string
		wantClassAfter string
		wantDelivered  bool
	}{
		// Terminal classes: a late 'delivered' is a no-op on classification.
		{"hard_bounce_preserved", "bounced_hard", "bounced_hard", false},
		{"soft_bounce_preserved", "bounced_soft", "bounced_soft", false},
		{"rejected_preserved", "rejected", "rejected", false},
		{"complaint_preserved", "complaint", "complaint", false},
		{"unsubscribed_preserved", "unsubscribed", "unsubscribed", false},
		// Non-terminal classes: a 'delivered' SHOULD win (deferred is transient;
		// 'success' is the worker's API-acceptance placeholder).
		{"deferred_upgraded", "deferred", "delivered", true},
		{"success_upgraded", "success", "delivered", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			providerID := "msg-guard-" + c.name + "-" + uuid.NewString()[:8]
			seedForwarderSent(t, db, providerID, c.seedClass)

			body := `{"event":"delivered","email":"u@example.com","message-id":"` + providerID + `"}`
			resp := postBrevoTx(t, app, testBrevoTxSecret, body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d; want 200", resp.StatusCode)
			}
			row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if row.Classification != c.wantClassAfter {
				t.Errorf("seed=%q: classification = %q; want %q", c.seedClass, row.Classification, c.wantClassAfter)
			}
			if (row.DeliveredAt != nil) != c.wantDelivered {
				t.Errorf("seed=%q: delivered_at set = %v; want %v", c.seedClass, row.DeliveredAt != nil, c.wantDelivered)
			}
		})
	}
}

// ── 4. idempotency: a re-delivery of the same 'delivered' event is a no-op on
//        the value side and does NOT push delivered_at backwards (GREATEST).

func TestBrevoTxWebhook_RealDB_DeliveredIsIdempotent(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	providerID := "msg-idem-" + uuid.NewString()[:8]
	seedForwarderSent(t, db, providerID, "success")
	app := brevoTxRealApp(t, db)
	body := `{"event":"delivered","email":"u@example.com","message-id":"` + providerID + `"}`

	// First delivery stamps delivered_at.
	if resp := postBrevoTx(t, app, testBrevoTxSecret, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("first POST status = %d; want 200", resp.StatusCode)
	}
	first, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
	if err != nil || first.DeliveredAt == nil {
		t.Fatalf("after first delivery: row=%+v err=%v", first, err)
	}
	firstTS := *first.DeliveredAt

	// A re-delivery (Brevo retry) must keep classification + must not move
	// delivered_at backwards (GREATEST). It may bump forward by sub-second; we
	// assert it never regresses.
	time.Sleep(10 * time.Millisecond)
	if resp := postBrevoTx(t, app, testBrevoTxSecret, body); resp.StatusCode != http.StatusOK {
		t.Fatalf("second POST status = %d; want 200", resp.StatusCode)
	}
	second, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, providerID)
	if err != nil {
		t.Fatalf("Lookup after re-delivery: %v", err)
	}
	if second.Classification != "delivered" {
		t.Errorf("classification after re-delivery = %q; want delivered", second.Classification)
	}
	if second.DeliveredAt == nil || second.DeliveredAt.Before(firstTS) {
		t.Errorf("delivered_at regressed: first=%v second=%v (GREATEST must keep it monotonic)", firstTS, second.DeliveredAt)
	}
}

// ── 5. unknown messageId (no matching row) → 200 matched:false, NO row created.

func TestBrevoTxWebhook_RealDB_UnknownMessageIDIsNoOp(t *testing.T) {
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()
	app := brevoTxRealApp(t, db)

	orphanID := "msg-orphan-" + uuid.NewString()[:8]
	body := `{"event":"delivered","email":"u@example.com","message-id":"` + orphanID + `"}`
	resp := postBrevoTx(t, app, testBrevoTxSecret, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d; want 200 (Brevo retries on non-2xx — orphans must NOT amplify retry)", resp.StatusCode)
	}
	// The handler must NEVER INSERT a ledger row for an orphan event.
	if _, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, orphanID); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("orphan messageId must leave no forwarder_sent row; lookup err = %v (want sql.ErrNoRows)", err)
	}
}
