package handlers_test

// billing_webhook_team_not_found_test.go — Wave-3 chaos verify P3
// (2026-05-21) regression.
//
// A signed Razorpay webhook whose notes.team_id (or subscription_id fallback)
// references a team that does not exist in our DB is an operationally
// interesting signal: typo'd dashboard notes, deleted-team race, synthetic
// chaos probe, or attacker probing valid-signature paths. The pre-fix path
// returned the 404 ("team_not_found") to Razorpay but left no audit_log
// row — which meant an operator had to grep NR for the slog line, and a
// burst against the path raised no signal at all.
//
// This test exercises the full live path: POST a signed subscription.charged
// payload with a valid signature, a valid plan_id (so the handler reaches
// UpgradeTeamAllTiersWithSubscription), and a syntactically-valid-but-
// unknown team_id, then assert (a) 404 status, (b) audit_log row with kind
// 'razorpay.webhook.team_not_found' carrying event_type + event_id +
// notes_team_id + subscription_id in metadata, (c) Prometheus counter
// razorpay_webhook_team_not_found_total ticks up.
//
// Requires TEST_DATABASE_URL — the audit row insert is the artifact we
// assert on (no fakes — the audit emit path is the bug class we're
// guarding against).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/metrics"
	"instant.dev/internal/testhelpers"
)

// TestRazorpayWebhook_TeamNotFound_EmitsAudit pins the contract: a
// signed Razorpay subscription.charged event whose notes.team_id refers
// to a non-existent team must (1) return 404, (2) increment the
// dedicated Prometheus counter, and (3) leave an audit_log row that an
// operator dashboard can chart.
//
// The team_id is a real UUID (uuid.New()) but NOT inserted into the
// teams table, so models.UpgradeTeamAllTiersWithSubscription returns
// models.ErrTeamNotFound when it sees zero rows affected — that's the
// branch we're verifying audits correctly.
func TestRazorpayWebhook_TeamNotFound_EmitsAudit(t *testing.T) {
	if testhelpersSkipNoDB(t) {
		return
	}

	// Use the shared billingWebhookDBApp helper so the cfg has valid
	// RazorpayPlanID* values — the handler must reach
	// UpgradeTeamAllTiersWithSubscription (which returns ErrTeamNotFound
	// when no team row matches), not be short-circuited by the
	// "unknown plan_id" or "unknown tier" F3 branches above it.
	db, dbCleanup := testhelpers.SetupTestDB(t)
	defer dbCleanup()

	app, cfg := billingWebhookDBApp(t, db)

	// Choose unique identifiers so concurrent test runs do not collide on
	// audit_log row reads. The team_id is a fresh UUID NOT in `teams` —
	// UpgradeTeamAllTiersWithSubscription will see 0 rows affected and
	// return ErrTeamNotFound, the branch we're verifying.
	bogusTeamID := uuid.NewString()
	subscriptionID := "sub_team_not_found_" + uuid.NewString()
	eventID := "evt_team_not_found_" + uuid.NewString()

	// Snapshot the Prom counter so we can assert exact +1 delta. The
	// metric is global so a concurrent test in the same package could in
	// principle perturb it; +1 is the most precise contract we can pin
	// without serialising the whole test binary.
	before := testutil.ToFloat64(metrics.RazorpayWebhookTeamNotFound)

	payload := makeSubscriptionChargedPayloadWithPlan(t, bogusTeamID, subscriptionID, cfg.RazorpayPlanIDPro)
	sig := signRazorpayPayload(t, testWebhookSecret, payload)
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	req.Header.Set("X-Razorpay-Event-Id", eventID)

	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"signed webhook with unknown team_id must return 404 so Razorpay does not retry (4xx = non-retryable)")

	// Body shape: {"ok":false,"error":"team_not_found"}.
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"], "404 envelope must report ok:false")
	assert.Equal(t, "team_not_found", body["error"], "404 envelope must carry the stable 'team_not_found' error code")

	// The audit emit runs in a safego.Go goroutine — give it a bounded
	// wait for the row to land. The handler's bounded-timeout is 3s; we
	// poll generously here, but a healthy emit lands well under 500ms.
	var auditKind, summary, metaText string
	var foundRow bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		row := db.QueryRow(`
			SELECT kind, summary, metadata::text
			  FROM audit_log
			 WHERE kind = 'razorpay.webhook.team_not_found'
			   AND metadata->>'event_id' = $1
			 ORDER BY created_at DESC
			 LIMIT 1`, eventID)
		if err := row.Scan(&auditKind, &summary, &metaText); err == nil {
			foundRow = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.True(t, foundRow,
		"expected an audit_log row with kind='razorpay.webhook.team_not_found' and metadata.event_id=%q within 5s — operator dashboard will not see this signal otherwise",
		eventID)

	assert.Equal(t, "razorpay.webhook.team_not_found", auditKind,
		"audit row kind must match the constant in models/audit_kinds.go (any drift breaks the NR alert filter)")
	assert.NotEmpty(t, summary,
		"audit row summary must be non-empty so the dashboard's Recent Activity feed can render a row")

	// Metadata shape: every documented field must be present.
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(metaText), &meta),
		"metadata must be valid JSON: %s", metaText)
	assert.Equal(t, "subscription.charged", meta["event_type"],
		"metadata.event_type must mirror the Razorpay event name")
	assert.Equal(t, eventID, meta["event_id"],
		"metadata.event_id must mirror the X-Razorpay-Event-Id header so operators can correlate against Razorpay's delivery log")
	assert.Equal(t, bogusTeamID, meta["notes_team_id"],
		"metadata.notes_team_id must mirror the payload notes.team_id verbatim (it's a UUID, no PII concerns)")
	assert.Equal(t, subscriptionID, meta["subscription_id"],
		"metadata.subscription_id must mirror the parsed subscription entity id")
	// source_ip_subnet is present (masked) — exact value depends on the
	// httptest client IP; assert presence not contents.
	_, hasSubnet := meta["source_ip_subnet"]
	assert.True(t, hasSubnet,
		"metadata.source_ip_subnet must be present so a sustained-burst signal can be charted by subnet")

	// CRITICAL: metadata must NOT carry payload PII (email, raw payload, etc.).
	assert.NotContains(t, meta, "email",
		"metadata must not include payload.email — this audit kind is operator-only signal, no customer PII")
	assert.NotContains(t, meta, "payload",
		"metadata must not include the raw payload — too verbose for an audit row + we don't want to persist customer-controlled bytes")

	// Prom counter incremented by exactly one (we posted exactly one webhook).
	after := testutil.ToFloat64(metrics.RazorpayWebhookTeamNotFound)
	assert.Equal(t, 1.0, after-before,
		"razorpay_webhook_team_not_found_total must increment by exactly 1 for one team_not_found webhook (got delta %f)", after-before)

	// Cleanup the test row so a re-run of the same test file does not
	// accumulate rows.
	_, _ = db.Exec(`DELETE FROM audit_log WHERE metadata->>'event_id' = $1`, eventID)
}
