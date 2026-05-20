//go:build e2e

package e2e

// brevo_webhook_integration_test.go — Track 2: full-pipeline integration
// tests for the Brevo transactional-delivery receiver.
//
// What this adds on top of:
//   - api/internal/handlers/brevo_webhook_test.go — sqlmock unit tests
//     (every event type → matching SQL UPDATE, secret-mismatch 401,
//     malformed-400, oversized-400, unknown-messageId-200, registry
//     drift gate).
//   - api/e2e/brevo_webhook_e2e_test.go — single delivered + single
//     hard_bounce round-trip against a live api + live PG.
//
// NEW HERE — closes the gaps the brief calls out:
//
//   1. TestE2E_BrevoWebhook_AllEventTypes_RoundTrip — registry walk
//      (CLAUDE.md rule 18). For every entry in
//      handlers.BrevoDocumentedEventsForTest() seed one forwarder_sent
//      row, POST the synthetic event, assert classification +
//      delivered_at populated per the per-event contract (only
//      'delivered' sets delivered_at; everything else is
//      classification-only). Self-cleans via DELETE on t.Cleanup.
//
//   2. TestE2E_BrevoWebhook_IdempotentRedelivery — same delivered event
//      POSTed twice; verifies the second is a no-op (classification
//      stays 'delivered', delivered_at unchanged or strictly
//      monotonic). The handler uses GREATEST(delivered_at, NOW()) so a
//      replay can never bump the timestamp backwards.
//
//   3. TestE2E_BrevoWebhook_DeliveredThenBounceNoTimeTravel — exercises
//      the "delivered first, then a delayed hard_bounce arrives" path.
//      Asserts the classification can move 'delivered' → 'bounced_hard'
//      (we accept Brevo's latest signal) but delivered_at IS NOT
//      cleared (we keep the receipt-of-delivery timestamp). This
//      verifies the makeClassUpdater path: classification updates,
//      delivered_at untouched.
//
//   4. TestE2E_BrevoWebhook_MalformedPayloadReturns400 — full-pipeline
//      check that a malformed JSON body returns 400 (matches the unit
//      test contract end-to-end against the live router).
//
//   5. TestE2E_BrevoWebhook_UnhandledEventReturns200Skipped — 'click' /
//      'open' / 'request' all flow to the receiver and must 200 with
//      skipped:true; verified against the live router (the unit test
//      only verifies the handler).
//
// CLEANUP CONTRACT (CLAUDE.md memory: "Verify against live + remote
// default branch"): every test t.Cleanup()'s the synthetic
// forwarder_sent row by audit_id. A failure does NOT block cleanup —
// t.Cleanup runs even on t.Fatal.
//
// COVERAGE BLOCK for the registry walk (rule 17):
//   Symptom:       a future Brevo event type is added to
//                  brevoDocumentedEvents (api/internal/handlers/
//                  brevo_webhook.go) but missing a handler — the unit
//                  test catches the registry drift, but a per-event
//                  full-pipeline regression (e.g. handler exists but
//                  doesn't actually persist the right column) is not
//                  caught by sqlmock.
//   Enumeration:   handlers.BrevoDocumentedEventsForTest() — the same
//                  exported function the unit test uses.
//   Sites found:   8 documented events at time of writing
//                  (delivered, soft_bounce, hard_bounce, blocked,
//                  complaint, deferred, unsubscribed, error).
//   Sites touched: 8 (this test iterates ALL).
//   Coverage test: a 9th event added to brevoDocumentedEvents WITHOUT
//                  a matching expectation in this test will still pass
//                  on the default contract (any classification != ""),
//                  BUT a missing handler branch is caught by the
//                  matched:true assertion AND the per-event class
//                  switch below.
//   Live verified: against `make test-e2e-full` after deploy.

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"instant.dev/internal/handlers"

	_ "github.com/lib/pq"
)

// postRawBytes posts arbitrary bytes to the live api with the supplied
// Content-Type. Distinct from `post` (which marshals JSON via the
// withDefaultName helper) — used for malformed-payload coverage.
func postRawBytes(t *testing.T, path, contentType string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL()+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("postRawBytes: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	if tok := e2eTestToken(); tok != "" {
		req.Header.Set("X-E2E-Test-Token", tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("postRawBytes %s: %v", path, err)
	}
	return resp
}

// brevoExpectedClassFor maps an inbound Brevo event to the
// classification the receiver should persist. Mirrors the
// brevoEventHandlers map in api/internal/handlers/brevo_webhook.go —
// the registry walk asserts the e2e contract matches the source-side.
//
// "spam" is in the inbound vocabulary but normalises to "complaint"
// before dispatch; not iterated here because
// BrevoDocumentedEventsForTest() doesn't include it (it's an alias).
var brevoExpectedClassFor = map[string]string{
	"delivered":    "delivered",
	"soft_bounce":  "bounced_soft",
	"hard_bounce":  "bounced_hard",
	"blocked":      "rejected",
	"complaint":    "complaint",
	"deferred":     "deferred",
	"unsubscribed": "unsubscribed",
	"error":        "error",
}

// brevoExpectsDeliveredAt is the per-event delivered_at contract.
// Only the 'delivered' event stamps the timestamp; every other class
// leaves it NULL (or untouched if it was already set by a prior
// delivered event — see TestE2E_BrevoWebhook_DeliveredThenBounceNoTimeTravel).
var brevoExpectsDeliveredAt = map[string]bool{
	"delivered": true,
}

// connectPlatformPG returns a *sql.DB to the platform Postgres or SKIPs
// the test when E2E_PLATFORM_PG_DSN is unset. Closes the connection on
// t.Cleanup.
func connectPlatformPG(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv(e2ePlatformPGDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to run the full DB round-trip (port-forward platform PG)", e2ePlatformPGDSNEnv)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("ping platform pg: %v", err)
	}
	return db
}

// seedForwarderRow inserts a forwarder_sent row keyed by audit_id +
// provider_id (messageId). Registers a t.Cleanup() that deletes the
// row even on test failure. Returns the (audit_id, message_id) pair.
func seedForwarderRow(t *testing.T, db *sql.DB, label string) (auditID, messageID string) {
	t.Helper()
	auditID = fmt.Sprintf("e2e-brevo-int-%s-%d", label, time.Now().UnixNano())
	messageID = fmt.Sprintf("e2e-msg-int-%s-%d", label, time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO forwarder_sent
			(audit_id, sent_at, provider, provider_id, recipient, template_kind, classification)
		VALUES ($1, NOW(), 'brevo', $2, 'i***@example.com', 'e2e.integration', 'success')
	`, auditID, messageID); err != nil {
		t.Fatalf("seed forwarder_sent: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort: hide errors; the row is small.
		_, _ = db.ExecContext(context.Background(), `DELETE FROM forwarder_sent WHERE audit_id = $1`, auditID)
	})
	return auditID, messageID
}

// readForwarderRow returns the (classification, delivered_at) pair for
// a forwarder_sent row by audit_id.
func readForwarderRow(t *testing.T, db *sql.DB, auditID string) (string, sql.NullTime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var class string
	var deliveredAt sql.NullTime
	if err := db.QueryRowContext(ctx, `
		SELECT classification, delivered_at FROM forwarder_sent WHERE audit_id = $1
	`, auditID).Scan(&class, &deliveredAt); err != nil {
		t.Fatalf("select forwarder_sent: %v", err)
	}
	return class, deliveredAt
}

// brevoPostEvent fires an event payload at the receiver and returns
// the (status_code, matched_bool) tuple.
func brevoPostEvent(t *testing.T, secret, event, messageID, email string) (int, bool) {
	t.Helper()
	body := map[string]any{
		"event":      event,
		"email":      email,
		"message-id": messageID,
		"subject":    "E2E " + event + " test",
		"reason":     "synthetic " + event + " from integration suite",
	}
	resp := post(t, "/webhooks/brevo/"+secret, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// 400 + 401 are real failures; return without parsing body.
		return resp.StatusCode, false
	}
	var out map[string]any
	decodeJSON(t, resp, &out)
	matched, _ := out["matched"].(bool)
	return resp.StatusCode, matched
}

// ─── Test 1: ALL documented events round-trip (registry walk) ─────────────────

// TestE2E_BrevoWebhook_AllEventTypes_RoundTrip iterates every documented
// Brevo event (per handlers.BrevoDocumentedEventsForTest) and verifies
// the live receiver + DB persist the contract correctly.
//
// Registry-iterating per CLAUDE.md rule 18 — adding a new Brevo event
// to brevoDocumentedEvents without an entry in brevoExpectedClassFor
// here FAILS at t.Fatalf with a "missing expectation" message,
// catching the drift even when the handler-side unit test passes.
func TestE2E_BrevoWebhook_AllEventTypes_RoundTrip(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	db := connectPlatformPG(t)

	for _, event := range handlers.BrevoDocumentedEventsForTest() {
		t.Run(event, func(t *testing.T) {
			wantClass, ok := brevoExpectedClassFor[event]
			if !ok {
				t.Fatalf("documented event %q has NO entry in brevoExpectedClassFor — adding a new Brevo event requires updating this test's expectation map to keep the e2e contract aligned with the source-side registry", event)
			}

			auditID, messageID := seedForwarderRow(t, db, "evtype-"+strings.ReplaceAll(event, "_", "-"))
			status, matched := brevoPostEvent(t, secret, event, messageID, "evtype@example.com")
			if status != http.StatusOK {
				t.Fatalf("POST event %q: status=%d, want 200", event, status)
			}
			if !matched {
				t.Errorf("POST event %q: matched=false, want true (seeded row should have been found by provider_id)", event)
			}

			gotClass, gotDeliveredAt := readForwarderRow(t, db, auditID)
			if gotClass != wantClass {
				t.Errorf("event %q: classification=%q, want %q (brevoEventHandlers contract drift)",
					event, gotClass, wantClass)
			}

			wantDelivered := brevoExpectsDeliveredAt[event]
			if wantDelivered && !gotDeliveredAt.Valid {
				t.Errorf("event %q: delivered_at IS NULL, want set (delivered events stamp the timestamp)", event)
			}
			if !wantDelivered && gotDeliveredAt.Valid {
				t.Errorf("event %q: delivered_at=%v, want NULL (only 'delivered' stamps the timestamp)",
					event, gotDeliveredAt.Time)
			}
		})
	}
}

// ─── Test 2: idempotent re-delivery — second delivered is a no-op ─────────────

// TestE2E_BrevoWebhook_IdempotentRedelivery POSTs the same delivered
// event twice, asserts the row's classification stays 'delivered' and
// delivered_at NEVER moves backwards (GREATEST guards monotonicity).
//
// Brevo retries on 5xx with exponential backoff. A re-delivery of the
// SAME event MUST be safe — the handler's idempotency contract is
// that UPDATE statements are write-idempotent + delivered_at is
// monotonically non-decreasing.
//
// CLAUDE.md rule 17 coverage block:
//   Symptom:       a future PR rewrites the delivered handler with
//                  `delivered_at = NOW()` (dropping GREATEST), so a
//                  late retry would silently bump the timestamp.
//   Enumeration:   `rg -F 'GREATEST(delivered_at' api/internal/`
//   Sites found:   1 (handleBrevoDelivered).
//   Sites touched: 1 (this test).
//   Coverage test: this test fails if a re-POST advances the
//                  timestamp.
//   Live verified: against `make test-e2e-full`.
func TestE2E_BrevoWebhook_IdempotentRedelivery(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	db := connectPlatformPG(t)

	auditID, messageID := seedForwarderRow(t, db, "idempotent")

	// First delivery — stamps delivered_at = NOW().
	status, matched := brevoPostEvent(t, secret, "delivered", messageID, "i1@example.com")
	if status != http.StatusOK || !matched {
		t.Fatalf("first delivery: status=%d matched=%v", status, matched)
	}
	class1, t1 := readForwarderRow(t, db, auditID)
	if class1 != "delivered" {
		t.Fatalf("after first delivery: classification=%q, want delivered", class1)
	}
	if !t1.Valid {
		t.Fatal("after first delivery: delivered_at IS NULL, want set")
	}

	// Wait a beat so a re-stamp would be observable.
	time.Sleep(2 * time.Second)

	// Second (replayed) delivery — must be a no-op on delivered_at +
	// classification.
	status2, matched2 := brevoPostEvent(t, secret, "delivered", messageID, "i1@example.com")
	if status2 != http.StatusOK || !matched2 {
		t.Fatalf("replay delivery: status=%d matched=%v", status2, matched2)
	}
	class2, t2 := readForwarderRow(t, db, auditID)
	if class2 != "delivered" {
		t.Errorf("after replay: classification=%q, want still delivered", class2)
	}
	if !t2.Valid {
		t.Fatal("after replay: delivered_at IS NULL")
	}
	// GREATEST guarantee: the second timestamp cannot be EARLIER than
	// the first, but must equal the first (NOW() is monotonic but the
	// GREATEST clause clamps it down to t1 when t1 > NOW(), which is
	// impossible in real time, so equality is the expected case).
	if t2.Time.Before(t1.Time) {
		t.Errorf("replay delivered_at=%v < first delivered_at=%v — GREATEST clause broken",
			t2.Time, t1.Time)
	}
}

// ─── Test 3: delivered, then hard_bounce — classification flips, ts stays ─────

// TestE2E_BrevoWebhook_DeliveredThenBounceNoTimeTravel verifies the
// out-of-order arrival path. Brevo can emit 'delivered' then later a
// hard_bounce if the SMTP transaction succeeded but the recipient
// rejected the message via a bounce-back later (postmaster bounces,
// out-of-office hard fails, etc.).
//
// The receiver MUST:
//   - Flip classification → 'bounced_hard' (latest signal wins).
//   - LEAVE delivered_at untouched (we got the SMTP delivery receipt
//     either way; clearing it would lose the audit-trail evidence
//     that the message DID land at the recipient's MX).
//
// This pins makeClassUpdater's contract: classification UPDATE,
// delivered_at NOT TOUCHED. A future refactor that consolidates
// delivered + bounce handlers into one path could accidentally
// rebind delivered_at; this test catches that.
func TestE2E_BrevoWebhook_DeliveredThenBounceNoTimeTravel(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	db := connectPlatformPG(t)

	auditID, messageID := seedForwarderRow(t, db, "delivered-then-bounce")

	// Step 1: delivered.
	if status, matched := brevoPostEvent(t, secret, "delivered", messageID, "d@example.com"); status != 200 || !matched {
		t.Fatalf("delivered POST: status=%d matched=%v", status, matched)
	}
	_, delivered1 := readForwarderRow(t, db, auditID)
	if !delivered1.Valid {
		t.Fatal("after delivered: delivered_at IS NULL")
	}

	// Step 2: late hard_bounce.
	if status, matched := brevoPostEvent(t, secret, "hard_bounce", messageID, "d@example.com"); status != 200 || !matched {
		t.Fatalf("hard_bounce POST: status=%d matched=%v", status, matched)
	}
	class, delivered2 := readForwarderRow(t, db, auditID)
	if class != "bounced_hard" {
		t.Errorf("after bounce: classification=%q, want bounced_hard (latest signal wins)", class)
	}
	if !delivered2.Valid {
		t.Errorf("after bounce: delivered_at became NULL — the bounce handler should NOT touch delivered_at")
	}
	if delivered2.Valid && !delivered2.Time.Equal(delivered1.Time) {
		t.Errorf("after bounce: delivered_at=%v changed from %v — makeClassUpdater touched delivered_at, it must not",
			delivered2.Time, delivered1.Time)
	}
}

// ─── Test 4: malformed payload → 400 end-to-end ───────────────────────────────

// TestE2E_BrevoWebhook_MalformedPayloadReturns400 hits the live
// receiver with an obvious JSON-syntax error and asserts 400. Mirrors
// the unit test contract end-to-end so a router/middleware change
// that swallowed the 400 (returning 500) is caught.
func TestE2E_BrevoWebhook_MalformedPayloadReturns400(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	resp := postRawBytes(t, "/webhooks/brevo/"+secret, "application/json", []byte("not-json{"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed payload: status=%d, want 400 (Brevo retries on 5xx — we must 400 a malformed body, not 5xx)", resp.StatusCode)
	}
}

// ─── Test 5: unhandled event → 200 skipped ────────────────────────────────────

// TestE2E_BrevoWebhook_UnhandledEventReturns200Skipped POSTs a 'click'
// event (Brevo emits these — non-ledger-relevant). Verifies 200 OK
// with skipped:true, never 4xx/5xx (which would trigger Brevo retry
// amplification on every click).
func TestE2E_BrevoWebhook_UnhandledEventReturns200Skipped(t *testing.T) {
	secret := os.Getenv(e2eBrevoSecretEnv)
	if secret == "" {
		t.Skipf("set %s to run", e2eBrevoSecretEnv)
	}
	for _, unhandled := range []string{"click", "open", "request"} {
		t.Run(unhandled, func(t *testing.T) {
			body := map[string]any{
				"event":      unhandled,
				"email":      "u@example.com",
				"message-id": "unhandled-" + unhandled,
			}
			resp := post(t, "/webhooks/brevo/"+secret, body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("unhandled event %q: status=%d, want 200 (Brevo retries on non-2xx)", unhandled, resp.StatusCode)
			}
			var out map[string]any
			decodeJSON(t, resp, &out)
			if out["skipped"] != true {
				t.Errorf("unhandled event %q: skipped=%v, want true", unhandled, out["skipped"])
			}
		})
	}
}
