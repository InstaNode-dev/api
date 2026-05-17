package handlers_test

// billing_webhook_dedup_race_test.go — P4 coverage: the Razorpay webhook
// dedup TOCTOU fix.
//
// Wave-3 moved the dedup INSERT to AFTER dispatch (so a failed event would
// retry). That re-opened a race: two concurrent deliveries of the SAME
// event both passed the `SELECT EXISTS` pre-check and both dispatched →
// double upgrade-audit / double dunning email.
//
// P4 replaces the pre-check with an ATOMIC claim at the START
// (`INSERT … ON CONFLICT DO NOTHING`, inspect RowsAffected). Exactly one
// concurrent delivery wins the claim and dispatches; every other delivery
// sees 0 rows and returns 200 {"deduped":true} without dispatching.
//
// Skips when TEST_DATABASE_URL is unset.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

// billingDBHandle bundles the test DB + cleanup so a P4 test can both drive
// the webhook handler AND inspect the razorpay_webhook_events table.
type billingDBHandle struct {
	db *sql.DB
	fn func()
}

// billingTestAppWithRealDBAndDB is billingTestAppWithRealDB but also hands
// back the underlying *sql.DB so the test can assert on the dedup table.
func billingTestAppWithRealDBAndDB(t *testing.T) (*fiber.App, billingDBHandle) {
	t.Helper()
	db, dbCleanup := testhelpers.SetupTestDB(t)
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
	}
	billing := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)
	return app, billingDBHandle{db: db, fn: dbCleanup}
}

// TestBillingWebhook_ConcurrentDeliveries_DispatchExactlyOnce is THE P4
// regression test: fire N concurrent deliveries of one event and assert
// EXACTLY ONE of them is the non-deduped (dispatching) call. Before P4 the
// TOCTOU window let multiple deliveries all dispatch.
func TestBillingWebhook_ConcurrentDeliveries_DispatchExactlyOnce(t *testing.T) {
	app, cleanup := billingTestAppWithRealDB(t)
	defer cleanup()

	eventID := "evt_p4_race_" + uuid.NewString()
	payload := makePaymentFailedPayloadWithEventID(t, eventID, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)

	const concurrency = 10
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		dispatched int // responses WITHOUT deduped:true — these actually ran the state machine
		deduped    int // responses WITH deduped:true
	)
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Razorpay-Signature", sig)
			req.Header.Set("X-Razorpay-Event-Id", eventID)

			resp, err := app.Test(req, 5000)
			if err != nil {
				t.Errorf("request failed: %v", err)
				return
			}
			defer resp.Body.Close()
			var body map[string]any
			if decErr := json.NewDecoder(resp.Body).Decode(&body); decErr != nil {
				t.Errorf("decode failed: %v", decErr)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			assert.Equal(t, http.StatusOK, resp.StatusCode, "every delivery must 200")
			if body["deduped"] == true {
				deduped++
			} else {
				dispatched++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, dispatched,
		"EXACTLY ONE concurrent delivery may dispatch — the rest must be deduped (P4 TOCTOU)")
	assert.Equal(t, concurrency-1, deduped,
		"every other concurrent delivery must return deduped:true without dispatching")
}

// TestBillingWebhook_ClaimRowPersistsAfterSuccess: after a successful
// dispatch the dedup claim row is present, so a later genuine replay is
// still suppressed (the claim is NOT released on success).
func TestBillingWebhook_ClaimRowPersistsAfterSuccess(t *testing.T) {
	app, cleanup := billingTestAppWithRealDBAndDB(t)
	defer cleanup.fn()

	eventID := "evt_p4_persist_" + uuid.NewString()
	payload := makePaymentFailedPayloadWithEventID(t, eventID, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)

	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", eventID)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// The claim row must remain after a successful dispatch.
	var n int
	require.NoError(t, cleanup.db.QueryRow(
		`SELECT count(*) FROM razorpay_webhook_events WHERE event_id = $1`, eventID,
	).Scan(&n))
	assert.Equal(t, 1, n, "a successfully-processed event must keep its dedup claim row")
}
