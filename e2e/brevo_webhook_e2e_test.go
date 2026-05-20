//go:build e2e

package e2e

// brevo_webhook_e2e_test.go — end-to-end test for the Brevo
// transactional-delivery receiver at POST /webhooks/brevo/:secret.
//
// This is the "201 ≠ delivered" gap-closing test. Hits the live api
// process with a synthetic Brevo event payload, verifies the
// forwarder_sent row gets updated, then cleans up.
//
// Requires:
//   - E2E_BASE_URL              — live api URL (port-forwarded or live deploy)
//   - E2E_BREVO_WEBHOOK_SECRET  — same value as BREVO_WEBHOOK_SECRET in the api
//   - E2E_PLATFORM_PG_DSN       — direct DSN to the platform Postgres so we
//                                 can seed + verify the forwarder_sent row.
//                                 Without this DSN we can still verify the
//                                 HTTP response (200 matched:false on an
//                                 unknown messageId), but not the round-trip
//                                 ledger update. The test SKIPs the
//                                 round-trip arm in that case.
//
// CLAUDE.md rule 14 (live-URL gate): this is exactly the verification
// surface required — synthetic webhook POST → real api process →
// real Postgres row update — that proves the receiver works end-to-end
// before any real Brevo traffic flows.

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const e2eBrevoSecretEnv = "E2E_BREVO_WEBHOOK_SECRET"
const e2ePlatformPGDSNEnv = "E2E_PLATFORM_PG_DSN"

// TestE2E_BrevoWebhook_OrphanMessageReturns200 hits the receiver with a
// messageId that doesn't match any ledger row and asserts a 200 OK with
// matched:false. This is the orphan-event path Brevo will hit on
// dashboard test sends + legacy rows + cross-cluster traffic — it must
// never 404 or 5xx (Brevo retries).
//
// No PG DSN required for this arm — it only verifies the HTTP contract.
func TestE2E_BrevoWebhook_OrphanMessageReturns200(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run (matches BREVO_WEBHOOK_SECRET in the api)", e2eBrevoSecretEnv)
	}

	body := map[string]any{
		"event":      "delivered",
		"email":      "e2e-orphan@example.com",
		"message-id": fmt.Sprintf("e2e-orphan-%d", time.Now().UnixNano()),
		"subject":    "E2E orphan test",
		"date":       "2026-05-20 08:00:00",
	}
	resp := post(t, "/webhooks/brevo/"+secret, body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("orphan event: want 200 (Brevo retries on non-2xx), got %d", resp.StatusCode)
	}
	var out map[string]any
	decodeJSON(t, resp, &out)
	if out["ok"] != true {
		t.Errorf("ok = %v; want true", out["ok"])
	}
	if out["matched"] != false {
		t.Errorf("matched = %v; want false (orphan messageId)", out["matched"])
	}
}

// TestE2E_BrevoWebhook_SecretMismatchReturns401 hits the receiver with
// the wrong URL secret. Public endpoint must reject all unauthenticated
// traffic — 401 not 200, not 404.
func TestE2E_BrevoWebhook_SecretMismatchReturns401(t *testing.T) {
	// Note: this test runs without E2E_BREVO_WEBHOOK_SECRET because it's
	// exercising the rejection path — any wrong secret works.
	resp := post(t, "/webhooks/brevo/wrong-secret-value-not-set-anywhere", map[string]any{
		"event":      "delivered",
		"message-id": "x",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad secret: want 401, got %d", resp.StatusCode)
	}
}

// TestE2E_BrevoWebhook_DeliveredEventUpdatesLedger is the full
// round-trip test. Seeds a forwarder_sent row, POSTs a 'delivered'
// event with that messageId, then verifies classification='delivered'
// and delivered_at IS NOT NULL.
//
// SKIPs if E2E_PLATFORM_PG_DSN is unset — without DB access we can't
// seed or verify the ledger row.
func TestE2E_BrevoWebhook_DeliveredEventUpdatesLedger(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	dsn := os.Getenv(e2ePlatformPGDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to run the full DB round-trip (port-forward platform PG)", e2ePlatformPGDSNEnv)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Seed a unique ledger row pointing at the synthetic messageId we'll
	// POST. audit_id is a TEXT primary key so we use a timestamped value
	// to keep concurrent test runs isolated.
	auditID := fmt.Sprintf("e2e-brevo-tx-%d", time.Now().UnixNano())
	messageID := fmt.Sprintf("e2e-msg-%d", time.Now().UnixNano())

	if _, err := db.ExecContext(ctx, `
		INSERT INTO forwarder_sent
			(audit_id, sent_at, provider, provider_id, recipient, template_kind, classification)
		VALUES ($1, NOW(), 'brevo', $2, 'e***@example.com', 'e2e.test', 'success')
	`, auditID, messageID); err != nil {
		t.Fatalf("seed forwarder_sent: %v", err)
	}
	// Best-effort cleanup so a re-run doesn't accumulate rows. We do
	// this unconditionally — even if the test fails the row should be
	// pruned, otherwise the next run sees a "duplicate audit_id" PK
	// collision risk for the same time-nano.
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM forwarder_sent WHERE audit_id = $1`, auditID)
	}()

	// Hit the receiver with a 'delivered' event for the seeded messageId.
	body := map[string]any{
		"event":      "delivered",
		"email":      "e2e-delivered@example.com",
		"message-id": messageID,
		"subject":    "E2E delivered test",
		"date":       "2026-05-20 08:00:00",
	}
	resp := post(t, "/webhooks/brevo/"+secret, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delivered event: want 200, got %d", resp.StatusCode)
	}
	var out map[string]any
	decodeJSON(t, resp, &out)
	if out["matched"] != true {
		t.Fatalf("matched = %v; want true (seeded row should have been found)", out["matched"])
	}

	// Verify the ledger row reflects the actual delivery, not the
	// API-acceptance state.
	var class string
	var deliveredAt sql.NullTime
	err = db.QueryRowContext(ctx, `
		SELECT classification, delivered_at
		  FROM forwarder_sent
		 WHERE audit_id = $1
	`, auditID).Scan(&class, &deliveredAt)
	if err != nil {
		t.Fatalf("select after update: %v", err)
	}
	if class != "delivered" {
		t.Errorf("classification = %q; want \"delivered\" (this is the whole point of the receiver — 201 ≠ delivered)", class)
	}
	if !deliveredAt.Valid {
		t.Error("delivered_at IS NULL; want set (the receiver should stamp it on 'delivered' events)")
	}
}

// TestE2E_BrevoWebhook_HardBounceUpdatesClassification is the failure
// path analogue of the delivered test. Seeds a row, POSTs a
// 'hard_bounce', verifies classification='bounced_hard' and
// delivered_at remains NULL (only 'delivered' sets delivered_at).
func TestE2E_BrevoWebhook_HardBounceUpdatesClassification(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	dsn := os.Getenv(e2ePlatformPGDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to run the full DB round-trip", e2ePlatformPGDSNEnv)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	auditID := fmt.Sprintf("e2e-brevo-hb-%d", time.Now().UnixNano())
	messageID := fmt.Sprintf("e2e-msg-hb-%d", time.Now().UnixNano())

	if _, err := db.ExecContext(ctx, `
		INSERT INTO forwarder_sent
			(audit_id, sent_at, provider, provider_id, recipient, template_kind, classification)
		VALUES ($1, NOW(), 'brevo', $2, 'h***@example.com', 'e2e.test', 'success')
	`, auditID, messageID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM forwarder_sent WHERE audit_id = $1`, auditID)
	}()

	body := map[string]any{
		"event":      "hard_bounce",
		"email":      "h@example.com",
		"message-id": messageID,
		"reason":     "550 5.1.1 user unknown",
	}
	resp := post(t, "/webhooks/brevo/"+secret, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("hard_bounce event: want 200, got %d", resp.StatusCode)
	}

	var class string
	var deliveredAt sql.NullTime
	if err := db.QueryRowContext(ctx, `
		SELECT classification, delivered_at FROM forwarder_sent WHERE audit_id = $1
	`, auditID).Scan(&class, &deliveredAt); err != nil {
		t.Fatalf("select: %v", err)
	}
	if class != "bounced_hard" {
		t.Errorf("classification = %q; want \"bounced_hard\"", class)
	}
	if deliveredAt.Valid {
		t.Errorf("delivered_at = %v; want NULL (only 'delivered' should stamp it)", deliveredAt.Time)
	}
}
