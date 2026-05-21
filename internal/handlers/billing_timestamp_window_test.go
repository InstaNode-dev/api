package handlers_test

// billing_timestamp_window_test.go — SRR security-cluster 2026-05-21 / H46 F3.
//
// Asserts the ±5-minute replay-window guard on Razorpay webhook
// payloads. The webhook's `created_at` (top-level Unix-second field) is
// part of the HMAC-signed body, so it cannot be tampered with by a
// replay attacker — they can only re-send the same body unchanged.
// Once created_at is older than 5 minutes, the re-send is rejected
// even though the signature still verifies.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

// testRazorpayWebhookSecret matches the value testhelpers.NewTestApp
// seeds into cfg.RazorpayWebhookSecret; signing a body with anything
// else makes the signature check fail before the timestamp guard runs.
const testRazorpayWebhookSecret = "razorpay_instant_dev_local_test_secret_for_ci"

// signBodyHexLocal is a local copy of the HMAC-SHA256 hex signer used
// by the e2e tests. Local copy keeps this unit-test file free of cross-
// package test deps so it can run inside the in-process app.Test loop.
func signBodyHexLocal(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// postRazorpayWithCreatedAt posts a minimal subscription.charged
// payload with the given created_at and returns the response.
func postRazorpayWithCreatedAt(t *testing.T, app interface {
	Test(req *http.Request, msTimeout ...int) (*http.Response, error)
}, secret string, createdAt int64) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"entity":     "event",
		"event":      "subscription.charged",
		"created_at": createdAt,
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(`{"id":"sub_test","status":"active","notes":{}}`),
			},
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", signBodyHexLocal(secret, body))

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

// TestVerifyRazorpayTimestamp_Predicate is a pure unit test for the
// timestamp-window decision function — no DB, no HTTP. Locks in the
// boundary semantics so a future "minor" tweak to the window constant
// or the abs-value handling fails loudly.
func TestVerifyRazorpayTimestamp_Predicate(t *testing.T) {
	now := int64(1_700_000_000) // fixed reference now-Unix
	cases := []struct {
		name     string
		created  int64
		rejected bool
	}{
		{"zero created_at backward-compat", 0, false},
		{"exactly now", now, false},
		{"one second old", now - 1, false},
		{"299 seconds old (inside window)", now - 299, false},
		{"300 seconds old (boundary)", now - 300, false},
		{"301 seconds old (outside window)", now - 301, true},
		{"hours old", now - 3600, true},
		{"299 seconds future", now + 299, false},
		{"301 seconds future", now + 301, true},
		{"hours in the future", now + 3600, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rejected, _ := handlers.VerifyRazorpayTimestampForTest(tc.created, now)
			assert.Equal(t, tc.rejected, rejected, "createdAt=%d, now=%d", tc.created, now)
		})
	}
}

// TestRazorpayWebhook_FreshTimestamp_ProceedsPastTimestampGuard asserts
// a payload with created_at == now passes the timestamp window and the
// handler reaches downstream processing (which may then 200 or fail for
// other reasons — we only care that the gate didn't reject).
func TestRazorpayWebhook_FreshTimestamp_ProceedsPastTimestampGuard(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	resp := postRazorpayWithCreatedAt(t, app, testRazorpayWebhookSecret, time.Now().Unix())
	defer io.Copy(io.Discard, resp.Body)
	defer resp.Body.Close()

	// A fresh-timestamp payload must NOT be rejected with the
	// timestamp_outside_window error. The downstream path may still
	// return 200 (the subscription is missing notes.team_id so the
	// handler will log and fail-safe), but it must NOT be a 400 with
	// the timestamp-window error code.
	if resp.StatusCode == http.StatusBadRequest {
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		assert.NotEqual(t, "timestamp_outside_window", body["error"],
			"a fresh-timestamp payload must not trip the replay-window guard")
	}
}

// TestRazorpayWebhook_StaleTimestamp_Returns400 asserts that a payload
// with created_at older than ±5 minutes is rejected with 400
// timestamp_outside_window even when the HMAC signature verifies. This
// is the core H46 F3 fix — without it, a captured legitimate payload
// can be replayed indefinitely.
func TestRazorpayWebhook_StaleTimestamp_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	// 10 minutes in the past — well outside the ±5-minute window.
	stale := time.Now().Add(-10 * time.Minute).Unix()
	resp := postRazorpayWithCreatedAt(t, app, testRazorpayWebhookSecret, stale)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a >5-minute-stale created_at must be rejected")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "timestamp_outside_window", body["error"],
		"error code must be timestamp_outside_window so operators/dashboards can distinguish from signature mismatch")
}

// TestRazorpayWebhook_FutureTimestamp_Returns400 asserts that a payload
// with created_at >5 minutes in the future is also rejected — covers
// the |now - created_at| > window case in both directions.
func TestRazorpayWebhook_FutureTimestamp_Returns400(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanRedis := testhelpers.SetupTestRedis(t)
	defer cleanRedis()

	app, cleanApp := testhelpers.NewTestAppWithServices(t, db, rdb, "postgres,redis,mongodb,queue,webhook,storage")
	defer cleanApp()

	future := time.Now().Add(10 * time.Minute).Unix()
	resp := postRazorpayWithCreatedAt(t, app, testRazorpayWebhookSecret, future)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"a >5-minute-future created_at must be rejected")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "timestamp_outside_window", body["error"])
}
