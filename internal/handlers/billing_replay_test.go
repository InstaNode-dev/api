package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// billingTestAppWithRealDB wires the Razorpay webhook handler against a real
// platform DB (the test fixture) so the replay-dedup INSERT can actually
// commit. Different from billingTestApp (nil DB) — that one exercises
// signature + logging paths only and would panic on the dedup INSERT.
func billingTestAppWithRealDB(t *testing.T) (*fiber.App, func()) {
	t.Helper()

	db, dbCleanup := testhelpers.SetupTestDB(t)

	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
	}
	emailClient := email.NewNoop()
	billing := handlers.NewBillingHandler(db, cfg, emailClient)

	app := fiber.New()
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", billing.RazorpayWebhook)

	return app, dbCleanup
}

// makePaymentFailedPayloadWithEventID is a variant of the existing helper
// that lets the test pin a specific event id so we can assert dedup
// behaviour by replaying the exact same payload.
//
// B11-P1 (2026-05-20): handlePaymentFailed no longer trusts payload.email —
// it resolves the dunning recipient via notes.team_id. The 3-arg overload
// (eventID, customerEmail) is kept for back-compat (subscription-less
// fixtures testing the dedup / no-team-resolvable path), and a 4-arg
// overload `WithTeam` lets the C5 dedup test wire a notes.team_id so the
// resolver lands on the seeded owner row. Callers that want a recipient
// to actually be looked up must use the WithTeam variant.
func makePaymentFailedPayloadWithEventID(t *testing.T, eventID string, customerEmail string) []byte {
	return makePaymentFailedPayloadWithEventIDAndTeam(t, eventID, customerEmail, "")
}

func makePaymentFailedPayloadWithEventIDAndTeam(t *testing.T, eventID, customerEmail, teamID string) []byte {
	t.Helper()
	entity := map[string]any{
		"id":            "pay_test123",
		"status":        "failed",
		"email":         customerEmail,
		"description":   "Test failed payment",
		"attempt_count": 1,
		"contact":       "+15551234567",
	}
	if teamID != "" {
		entity["notes"] = map[string]string{"team_id": teamID}
	}
	body := map[string]any{
		"id":     eventID,
		"entity": "event",
		"event":  "payment.failed",
		"payload": map[string]any{
			"payment": map[string]any{
				"entity": entity,
			},
		},
	}
	b, err := json.Marshal(body)
	require.NoError(t, err)
	return b
}

// TestBillingWebhook_Replay_SecondCallIsDeduped — the regression test for
// the loophole found 2026-05-13. Without replay protection, an attacker
// who captures one signed payload can re-POST it indefinitely; each call
// re-fires the state machine (re-issue dunning emails, re-emit audit rows,
// re-extend grace periods). This test pins the dedup contract: first call
// processes normally; second identical call returns 200 with deduped:true
// and does NOT re-fire side effects.
func TestBillingWebhook_Replay_SecondCallIsDeduped(t *testing.T) {
	app, cleanup := billingTestAppWithRealDB(t)
	defer cleanup()

	// Random event id so test reruns + parallel test files don't collide
	// on the dedup table.
	eventID := "evt_test_replay_" + uuid.NewString()
	payload := makePaymentFailedPayloadWithEventID(t, eventID, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Razorpay-Signature", sig)
		req.Header.Set("X-Razorpay-Event-Id", eventID)
		return req
	}

	// First call: processed.
	resp, err := app.Test(makeReq(), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body1 map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body1))
	assert.True(t, body1["ok"].(bool))
	_, deduped := body1["deduped"]
	assert.False(t, deduped, "first call must NOT carry deduped flag")

	// Second call with the same event_id: must be deduped.
	resp2, err := app.Test(makeReq(), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "replays should still 200 (Razorpay expects success or it retries)")
	var body2 map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&body2))
	assert.True(t, body2["ok"].(bool))
	assert.Equal(t, true, body2["deduped"], "second call MUST carry deduped:true")
}

// TestBillingWebhook_Replay_DifferentEventID_ProcessesIndependently — a
// second event with a different id is NOT deduped. This guards against
// over-aggressive blocking that would swallow legitimate consecutive
// events (e.g. a charge_failed followed by a charged event for the same
// subscription).
func TestBillingWebhook_Replay_DifferentEventID_ProcessesIndependently(t *testing.T) {
	app, cleanup := billingTestAppWithRealDB(t)
	defer cleanup()

	for i, eventID := range []string{"evt_unique_a_" + uuid.NewString(), "evt_unique_b_" + uuid.NewString()} {
		payload := makePaymentFailedPayloadWithEventID(t, eventID, "")
		sig := signRazorpayPayload(t, testWebhookSecret, payload)
		req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Razorpay-Signature", sig)
		req.Header.Set("X-Razorpay-Event-Id", eventID)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err, "request %d", i)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		_, deduped := body["deduped"]
		assert.False(t, deduped, "event %d (%s) must not be deduped — id is unique", i, eventID)
	}
}

// TestBillingWebhook_Replay_EventIDInBody_FallbackFromHeader — if Razorpay
// omits the X-Razorpay-Event-Id header (older API versions / proxy
// stripping) but the body carries `id`, the handler still dedups.
func TestBillingWebhook_Replay_EventIDInBody_FallbackFromHeader(t *testing.T) {
	app, cleanup := billingTestAppWithRealDB(t)
	defer cleanup()

	eventID := "evt_body_only_" + uuid.NewString()
	payload := makePaymentFailedPayloadWithEventID(t, eventID, "")
	sig := signRazorpayPayload(t, testWebhookSecret, payload)

	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Razorpay-Signature", sig)
		// Deliberately NO X-Razorpay-Event-Id header.
		return req
	}

	resp, err := app.Test(makeReq(), 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp2, err := app.Test(makeReq(), 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp2.Body).Decode(&body))
	assert.Equal(t, true, body["deduped"], "body.id fallback must still dedup")
}
