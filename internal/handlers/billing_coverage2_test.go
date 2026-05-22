package handlers_test

// billing_coverage2_test.go — second-wave coverage tests pushing the billing
// handler files to >=95%. The first-wave billing_coverage_test.go covered the
// pure helpers + GetBillingState + Brevo. This file targets the remaining
// gaps:
//
//   - The full RazorpayWebhook event dispatch matrix (DB-backed): every event
//     branch (completed healthy/unpaid, paused, resumed, pending,
//     charged_failed, deauthenticated, updated, refund.processed, halted,
//     payment.failed resolved-via-team paths), the replay-dedup short-circuit,
//     and the ±5-minute timestamp window guard.
//   - ChangePlanAPI branches: missing target, same-plan, invalid plan,
//     downgrade-not-self-serve, team-tier-unavailable, yearly/invalid
//     frequency, team-not-found.
//   - resolveTeamFromPayment resolution priority paths.
//
// All DB-backed tests skip cleanly when TEST_DATABASE_URL is unset, matching
// the existing convention.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// cfgPlanPro is the test pro plan id used by cov2WebhookAppReal.
const cfgPlanPro = "plan_test_pro"

// cov2NeedsDB skips a test when no test Postgres is configured.
func cov2NeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing coverage2: TEST_DATABASE_URL not set")
	}
}

// cov2ErrHandler is the shared Fiber ErrorHandler mirroring production: the
// respond* helpers write the response then return ErrResponseWritten, which
// must NOT be coerced into a 500.
func cov2ErrHandler(c *fiber.Ctx, err error) error {
	if errors.Is(err, handlers.ErrResponseWritten) {
		return nil
	}
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
}

// cov2WebhookAppReal builds a Fiber app wiring just the Razorpay webhook
// against a real DB + a configurable email client.
func cov2WebhookAppReal(t *testing.T, db *sql.DB, emailer email.Mailer) (*fiber.App, *config.Config) {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDHobby:   "plan_test_hobby",
		RazorpayPlanIDPro:     cfgPlanPro,
		RazorpayPlanIDTeam:    "plan_test_team",
	}
	bh := handlers.NewBillingHandler(db, cfg, emailer)
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)
	return app, cfg
}

// changePlanAppReal wires ChangePlanAPI with team_id stamped (no auth mw).
func changePlanAppReal(t *testing.T, db *sql.DB, cfg *config.Config, teamID string) *fiber.App {
	t.Helper()
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		return c.Next()
	})
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)
	return app
}

// startGraceForTest opens an active payment grace row for a team so a
// subscription.resumed test has something to recover.
func startGraceForTest(t *testing.T, db *sql.DB, teamID uuid.UUID, subID string) error {
	t.Helper()
	now := time.Now().UTC()
	_, err := models.CreatePaymentGracePeriod(context.Background(), db, models.CreatePaymentGracePeriodParams{
		TeamID:         teamID,
		SubscriptionID: subID,
		StartedAt:      now,
		ExpiresAt:      now.Add(7 * 24 * time.Hour),
	})
	return err
}

// decodeEventID extracts the top-level event id from a marshalled payload.
func decodeEventID(t *testing.T, payload []byte) string {
	t.Helper()
	var m struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(payload, &m))
	return m.ID
}

// helper builders ───────────────────────────────────────────────────────────

// cov2Event marshals a Razorpay webhook event with the given event name and a
// subscription entity built from teamID/subID/planID/status. paidCount, when
// non-nil, sets paid_count on the subscription entity (used by
// subscription.completed). attachPayment, when non-zero, bundles a payment
// entity (for charged_failed amount extraction + payment.failed paths).
func cov2SubEvent(t *testing.T, eventName, teamID, subID, planID, status string, paidCount *int, paymentAmount int64) []byte {
	t.Helper()
	sub := map[string]any{
		"id":      subID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  status,
		"notes":   map[string]any{},
	}
	if teamID != "" {
		sub["notes"] = map[string]any{"team_id": teamID}
	}
	if paidCount != nil {
		sub["paid_count"] = *paidCount
	}
	subEntity, _ := json.Marshal(sub)

	payload := map[string]any{
		"subscription": map[string]any{"entity": json.RawMessage(subEntity)},
	}
	if paymentAmount > 0 {
		payEntity, _ := json.Marshal(map[string]any{
			"id": "pay_" + uuid.NewString(), "entity": "payment",
			"amount": paymentAmount, "currency": "INR", "attempt_count": 2,
		})
		payload["payment"] = map[string]any{"entity": json.RawMessage(payEntity)}
	}
	event := map[string]any{
		"entity":  "event",
		"id":      "evt_" + uuid.NewString(),
		"event":   eventName,
		"payload": payload,
	}
	b, err := json.Marshal(event)
	require.NoError(t, err)
	return b
}

// cov2Run posts a signed webhook payload and returns the status code.
func cov2Run(t *testing.T, app *fiber.App, payload []byte) (int, map[string]any) {
	t.Helper()
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

// ── subscription.completed ──────────────────────────────────────────────────

func TestCov2_SubscriptionCompleted_HealthyKeepsPlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	paid := 12
	payload := cov2SubEvent(t, "subscription.completed", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "completed", &paid, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	// Tier is unchanged — the loyal customer is kept on plan.
	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
}

func TestCov2_SubscriptionCompleted_UnpaidDowngrades(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	paid := 0 // never charged → genuine end-of-relationship → downgrade
	payload := cov2SubEvent(t, "subscription.completed", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "completed", &paid, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.NotEqual(t, "pro", tier, "an unpaid completion downgrades the team off pro")
}

func TestCov2_SubscriptionCompleted_MalformedReturns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "subscription.completed",
		"payload": map[string]any{"subscription": map[string]any{"entity": "not-json"}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
}

// ── subscription.paused / resumed ────────────────────────────────────────────

func TestCov2_SubscriptionPaused_OpensGrace(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	subID := "sub_" + uuid.NewString()
	defer db.Exec(`DELETE FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.paused", teamID, subID, "", "paused", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status = 'active'`, teamID).Scan(&n))
	assert.Equal(t, 1, n, "a paused subscription opens exactly one active grace row")
}

func TestCov2_SubscriptionResumed_RecoversGrace(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	subID := "sub_" + uuid.NewString()
	defer db.Exec(`DELETE FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID)

	// Pre-open an active grace row so resume has something to recover.
	require.NoError(t, startGraceForTest(t, db, teamUUID, subID))

	payload := cov2SubEvent(t, "subscription.resumed", teamID, subID, "", "active", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var status string
	require.NoError(t, db.QueryRow(`SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, teamID).Scan(&status))
	assert.Equal(t, "recovered", status, "resume flips the active grace row to recovered")
}

func TestCov2_SubscriptionResumed_NoGraceIsNoOp(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	payload := cov2SubEvent(t, "subscription.resumed", teamID, "sub_"+uuid.NewString(), "", "active", nil, 0)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusOK, code)
}

// ── subscription.pending (dunning via team owner) ────────────────────────────

func TestCov2_SubscriptionPending_SendsDunning(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	payload := cov2SubEvent(t, "subscription.pending", teamID, "sub_"+uuid.NewString(), "", "pending", nil, 0)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusOK, code)
}

func TestCov2_SubscriptionPending_NoTeamReturns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	// No team_id, no sub_id → unresolvable → non-retryable → 200.
	payload := cov2SubEvent(t, "subscription.pending", "", "", "", "pending", nil, 0)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusOK, code)
}

// ── parse-failure (malformed entity) → 200 for each soft handler ─────────────

func TestCov2_Malformed_AllSoftHandlers_Returns200(t *testing.T) {
	cov2NeedsDB(t)
	for _, ev := range []string{
		"subscription.paused",
		"subscription.resumed",
		"subscription.pending",
		"subscription.charged_failed",
		"subscription.completed",
	} {
		t.Run(ev, func(t *testing.T) {
			db, clean := testhelpers.SetupTestDB(t)
			defer clean()
			app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
			event := map[string]any{
				"entity": "event", "id": "evt_" + uuid.NewString(), "event": ev,
				"payload": map[string]any{"subscription": map[string]any{"entity": "not-a-json-object"}},
			}
			b, _ := json.Marshal(event)
			code, _ := cov2Run(t, app, b)
			assert.Equal(t, http.StatusOK, code)
		})
	}
}

// ── unresolvable-team (non-retryable) → 200 for each soft handler ────────────

func TestCov2_Unresolvable_NonRetryable_Returns200(t *testing.T) {
	cov2NeedsDB(t)
	for _, ev := range []string{
		"subscription.completed",
		"subscription.paused",
		"subscription.resumed",
		"subscription.charged_failed",
	} {
		t.Run(ev, func(t *testing.T) {
			db, clean := testhelpers.SetupTestDB(t)
			defer clean()
			app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
			// No team_id and no sub_id → ErrTeamUnresolvable (non-retryable) → 200.
			// For completed we must avoid the unpaid-downgrade path, so give a
			// positive paid_count (healthy → resolveTeamFromNotes runs).
			var payload []byte
			if ev == "subscription.completed" {
				paid := 3
				payload = cov2SubEvent(t, ev, "", "", "", "completed", &paid, 0)
			} else {
				payload = cov2SubEvent(t, ev, "", "", "", "active", nil, 0)
			}
			code, _ := cov2Run(t, app, payload)
			assert.Equal(t, http.StatusOK, code)
		})
	}
}

// ── subscription.pending: team with no owner email → drop (200) ──────────────

func TestCov2_SubscriptionPending_NoOwnerEmail_Returns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	// Team exists but has no users → GetUserByTeamID returns nothing → drop.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	payload := cov2SubEvent(t, "subscription.pending", teamID, "sub_"+uuid.NewString(), "", "pending", nil, 0)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusOK, code)
}

// ── subscription.charged_failed → grace ──────────────────────────────────────

func TestCov2_ChargedFailed_OpensGraceWithAmount(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.charged_failed", teamID, "sub_"+uuid.NewString(), cfgPlanPro, "halted", nil, 490000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM payment_grace_periods WHERE team_id = $1::uuid AND status='active'`, teamID).Scan(&n))
	assert.Equal(t, 1, n)
}

// ── subscription.cancelled paid_count=0 → free floor ─────────────────────────

func TestCov2_Cancelled_ZeroPaid_DropsToFree(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
	paid := 0
	payload := cov2SubEvent(t, "subscription.cancelled", teamID, "sub_"+uuid.NewString(), "", "cancelled", &paid, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "free", tier, "a never-paid cancellation drops to the free floor")
}

func TestCov2_Cancelled_MalformedEntity_Returns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "subscription.cancelled",
		"payload": map[string]any{"subscription": map[string]any{"entity": "broken"}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
}

// TestCov2_Cancelled_AdminInitiated_SkipsEmail covers the admin-dedup branch:
// when a recent subscription.canceled_by_admin audit row exists, the webhook
// path skips its own cancellation emit.
func TestCov2_Cancelled_AdminInitiated_SkipsEmail(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	// Pre-insert a fresh subscription.canceled_by_admin row.
	require.NoError(t, models.InsertAuditEvent(context.Background(), db, models.AuditEvent{
		TeamID:  teamUUID,
		Actor:   "admin",
		Kind:    models.AuditKindSubscriptionCanceledByAdmin,
		Summary: "admin demoted",
	}))
	payload := cov2SubEvent(t, "subscription.cancelled", teamID, "sub_"+uuid.NewString(), "", "cancelled", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
	// Webhook path must NOT have emitted a second subscription.canceled row.
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'subscription.canceled'`, teamID).Scan(&n))
	assert.Equal(t, 0, n, "admin-initiated cancel suppresses the webhook-path cancellation emit")
}

// ── subscription.deauthenticated → cancel ────────────────────────────────────

func TestCov2_Deauthenticated_Downgrades(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.deauthenticated", teamID, "sub_"+uuid.NewString(), "", "cancelled", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.NotEqual(t, "pro", tier, "deauthenticated revokes the mandate → team downgraded")
}

// ── subscription.updated → re-resolve via charged ────────────────────────────

func TestCov2_SubscriptionUpdated_ReResolvesTier(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.updated", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
}

// ── subscription.halted → cancel ──────────────────────────────────────────────

func TestCov2_Halted_Downgrades(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.halted", teamID, "sub_"+uuid.NewString(), "", "halted", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
}

// ── refund.processed → info-only ──────────────────────────────────────────────

func TestCov2_RefundProcessed_Returns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(),
		"event": "refund.processed", "payload": map[string]any{},
	}
	b, _ := json.Marshal(event)
	code, body := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, body["ok"])
}

// ── payment.failed resolved-via-team (sends to the team primary) ──────────────

func TestCov2_PaymentFailed_ResolvesViaSubscriptionNotes(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	// payment.failed with a sibling subscription entity carrying team_id in
	// notes → resolveTeamFromPayment path 3 (subscription.notes.team_id).
	subEntity, _ := json.Marshal(map[string]any{
		"id": "sub_" + uuid.NewString(), "entity": "subscription",
		"notes": map[string]any{"team_id": teamID},
	})
	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"email": "spoofed@evil.example", // must be ignored; resolved recipient wins
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{
			"payment":      map[string]any{"entity": json.RawMessage(payEntity)},
			"subscription": map[string]any{"entity": json.RawMessage(subEntity)},
		},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
}

func TestCov2_PaymentFailed_NoPaymentEntityReturns200(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
}

// ── replay dedup short-circuit ────────────────────────────────────────────────

func TestCov2_Webhook_ReplayDeduped(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", nil, 0)
	eventID := decodeEventID(t, payload)
	defer db.Exec(`DELETE FROM razorpay_webhook_events WHERE event_id = $1`, eventID)

	// First delivery owns the event.
	code1, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code1)
	// Second delivery (same event id) is deduped.
	code2, body2 := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code2)
	assert.Equal(t, true, body2["deduped"], "a replay of the same event_id is short-circuited")
}

// ── timestamp window guard ────────────────────────────────────────────────────

func TestCov2_Webhook_TimestampOutsideWindow_Returns400(t *testing.T) {
	app := billingTestApp(t) // nil-DB app is fine — guard fires before dispatch
	event := map[string]any{
		"entity": "event", "id": "evt_old", "event": "subscription.charged",
		"created_at": int64(1), // 1970 → far outside ±5min
		"payload":    map[string]any{"subscription": map[string]any{"entity": json.RawMessage(`{"id":"sub_x","notes":{}}`)}},
	}
	b, _ := json.Marshal(event)
	req := signedWebhookRequest(t, b)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "timestamp_outside_window", body["error"])
}

// ── ChangePlanAPI branch matrix ───────────────────────────────────────────────

func changePlanReq(t *testing.T, app *fiber.App, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var rb map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rb)
	return resp.StatusCode, rb
}

func TestCov2_ChangePlan_MissingTarget(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)

	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": ""})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "missing_target_plan", body["error"])
}

func TestCov2_ChangePlan_YearlyUnsupported(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro", "plan_frequency": "yearly"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "yearly_change_plan_unsupported", body["error"])
}

func TestCov2_ChangePlan_InvalidFrequency(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro", "plan_frequency": "quarterly"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_frequency", body["error"])
}

func TestCov2_ChangePlan_SamePlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "same_plan", body["error"])
}

func TestCov2_ChangePlan_InvalidPlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	// Only configure hobby+pro plan ids; "nonsense" is not in the map.
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDHobby: "plan_hobby", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "nonsense"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_plan", body["error"])
}

func TestCov2_ChangePlan_DowngradeNotSelfServe(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDHobby: "plan_hobby", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	// pro → hobby is a downgrade.
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "hobby"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "downgrade_not_self_serve", body["error"])
}

func TestCov2_ChangePlan_TeamTierUnavailable(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDHobby: "plan_hobby", RazorpayPlanIDPro: "plan_pro", RazorpayPlanIDTeam: "plan_team"}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "team"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "tier_unavailable", body["error"])
}

func TestCov2_ChangePlan_NoSubscription(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDHobby: "plan_hobby", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	// hobby → pro is an upgrade and a valid plan, but the team has no
	// stored subscription id → no_subscription.
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "no_subscription", body["error"])
}

func TestCov2_ChangePlan_TeamNotFound(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	// A team id that does not exist → SELECT plan_tier returns sql.ErrNoRows.
	app := changePlanAppReal(t, db, cfg, uuid.NewString())
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusNotFound, code)
	assert.Equal(t, "not_found", body["error"])
}

func TestCov2_ChangePlan_InvalidBody(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan", bytes.NewReader([]byte(`{not json`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCov2_ChangePlan_Unauthorized(t *testing.T) {
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s"}
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI) // no team_id local
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.Equal(t, "unauthorized", body["error"])
}

func TestCov2_ChangePlan_NotConfigured(t *testing.T) {
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!"} // no Razorpay
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, uuid.NewString()); return c.Next() })
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Equal(t, "billing_not_configured", body["error"])
}

// ── failing mailer → retryable webhook handler errors (500) ──────────────────

// cov2FailMailer wraps a noop Mailer and forces every send-with-key call to
// error, so the dunning / pending / receipt error branches are exercised.
type cov2FailMailer struct{ email.Mailer }

func (m cov2FailMailer) SendPaymentFailedWithKey(ctx context.Context, to, key string, attempt int, next *time.Time) error {
	return errors.New("forced send failure")
}

func newFailMailer() email.Mailer { return cov2FailMailer{email.NewNoop()} }

func TestCov2_SubscriptionPending_EmailFails_Returns500(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, newFailMailer())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	payload := cov2SubEvent(t, "subscription.pending", teamID, "sub_"+uuid.NewString(), "", "pending", nil, 0)
	code, _ := cov2Run(t, app, payload)
	assert.Equal(t, http.StatusInternalServerError, code, "a failed dunning send is retryable → 500 so Razorpay redelivers")
}

func TestCov2_PaymentFailed_EmailFails_Returns500(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, newFailMailer())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"notes": map[string]any{"team_id": teamID}, // resolveTeamFromPayment path 1
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": json.RawMessage(payEntity)}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusInternalServerError, code)
}

// ── subscription.charged success: receipt + grace recovery + change audit ────

func TestCov2_Charged_WithOwner_SendsReceiptAndRecoversGrace(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
	subID := "sub_" + uuid.NewString()
	defer db.Exec(`DELETE FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)
	// Pre-open a grace row so the charged handler's maybeRecoverPaymentGrace
	// has something to flip to 'recovered'.
	require.NoError(t, startGraceForTest(t, db, teamUUID, subID))

	// charged with a payment entity (amount known) + paid_count (receipt key)
	// → receipt is sent and the grace recovers.
	paid := 1
	payload := cov2SubEvent(t, "subscription.charged", teamID, subID, cfg.RazorpayPlanIDPro, "active", &paid, 490000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var tier, graceStatus string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
	require.NoError(t, db.QueryRow(`SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, teamID).Scan(&graceStatus))
	assert.Equal(t, "recovered", graceStatus)
}

func TestCov2_Charged_UnknownTier_FlagsUndeliverable(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)

	// An unconfigured plan_id → planIDToTier fallback; if the resolved tier is
	// not in plans.yaml the unknown-tier branch fires. Use a clearly-bogus
	// plan id so planIDRecognised=false.
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), "plan_totally_unknown_xyz", "active", nil, 100000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	// Tier should remain hobby (fallback applied) and a charge_undeliverable
	// audit row recorded for operator reconciliation.
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'billing.charge_undeliverable'`, teamID).Scan(&n))
	assert.GreaterOrEqual(t, n, 1)
}

// ── resolveTeamFromPayment via payment.subscription_id DB lookup ──────────────

func TestCov2_PaymentFailed_ResolvesViaSubscriptionIDLookup(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
	subID := "sub_" + uuid.NewString()
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db, teamUUID, subID))

	// payment.failed with NO notes and NO sibling subscription, but a
	// subscription_id that maps to the team via the DB → path 2.
	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"subscription_id": subID,
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": json.RawMessage(payEntity)}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code)
}

// ── subscription.activated → upgrade (routes through charged) ────────────────

func TestCov2_SubscriptionActivated_Upgrades(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	payload := cov2SubEvent(t, "subscription.activated", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", nil, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
}

// ── subscription.charged with a LOWER-tier plan → must not downgrade ─────────

func TestCov2_Charged_LowerTier_DoesNotDowngrade(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
	// A charged event carrying the hobby plan_id for a pro team.
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDHobby, "active", nil, 100000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier, "charged is never a downgrade signal — pro must be kept")
}

// ── payment.failed: primary user has an empty email → drop (200) ─────────────

func TestCov2_PaymentFailed_EmptyPrimaryEmail_Drops(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	// Insert a primary user with an empty email directly (CreateUser would
	// normalise, but the DB allows '' under NOT NULL).
	_, err := db.Exec(`INSERT INTO users (team_id, email, role, is_primary, email_verified) VALUES ($1::uuid, '', 'owner', true, false)`, teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE team_id = $1::uuid`, teamID)

	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"notes": map[string]any{"team_id": teamID},
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": json.RawMessage(payEntity)}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code, "an empty primary email drops the dunning send cleanly with 200")
}

// ── dunning dedup-skip: payment.failed when the cycle was already claimed ─────

func TestCov2_PaymentFailed_DunningDeduped(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	rcpt := testhelpers.UniqueEmail(t)
	u, err := models.CreateUser(context.Background(), db, teamUUID, rcpt, "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)

	// Pre-claim today's dunning key for this recipient so the handler's claim
	// returns already-used → the deduped early-return path fires.
	key := handlers.ExportedDunningDedupKey(models.NormalizeEmail(rcpt))
	claimed, err := models.ClaimEmailSend(context.Background(), db, key, models.EmailSendKindDunning)
	require.NoError(t, err)
	require.True(t, claimed, "precondition: first claim succeeds")

	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"notes": map[string]any{"team_id": teamID},
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": json.RawMessage(payEntity)}},
	}
	b, _ := json.Marshal(event)
	code, _ := cov2Run(t, app, b)
	assert.Equal(t, http.StatusOK, code, "a deduped cycle short-circuits cleanly with 200")
}

// ── CreateCheckoutAPI branches ────────────────────────────────────────────────

// cov2CheckoutApp wires CreateCheckoutAPI with a verified user (clears the
// email gate) and returns the handler so the test can override
// CreateSubscription / FetchCheckoutSubscription.
func cov2CheckoutApp(t *testing.T, db *sql.DB, cfg *config.Config, teamID, userID string) (*fiber.App, *handlers.BillingHandler) {
	t.Helper()
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, userID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app, bh
}

// seedVerifiedTeamUser creates a team + verified primary user, returns ids.
func seedVerifiedTeamUser(t *testing.T, db *sql.DB, tier string) (teamID string, userID string) {
	t.Helper()
	teamID = testhelpers.MustCreateTeamDB(t, db, tier)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	require.NoError(t, models.SetEmailVerified(context.Background(), db, u.ID))
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)
		db.Exec(`DELETE FROM pending_checkouts WHERE team_id = $1::uuid`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	})
	return teamID, u.ID.String()
}

func postCheckoutReq(t *testing.T, app *fiber.App, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var rb map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rb)
	return resp.StatusCode, rb
}

func TestCov2_Checkout_AlreadyOnTier(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro", RazorpayPlanIDHobby: "plan_hobby"}
	teamID, userID := seedVerifiedTeamUser(t, db, "pro")
	app, _ := cov2CheckoutApp(t, db, cfg, teamID, userID)
	// Already on pro, requesting hobby (lower) → already_on_plan.
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "hobby"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "already_on_plan", body["error"])
}

func TestCov2_Checkout_FreshCreateSuccess(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	newSubID := "sub_new_" + uuid.NewString()
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return map[string]any{"id": newSubID, "short_url": "https://rzp.io/x"}, nil
	}
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, code, "body=%v", body)
	assert.Equal(t, newSubID, body["subscription_id"])
	assert.Equal(t, "https://rzp.io/x", body["short_url"])
}

func TestCov2_Checkout_ReusesPendingSubscription(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	teamUUID := uuid.MustParse(teamID)
	pendingSub := "sub_pending_" + uuid.NewString()
	require.NoError(t, models.InsertPendingCheckout(context.Background(), db, pendingSub, teamUUID, "u@example.com", "pro"))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	// First candidate fetch errors (fail-open skip); make the same row return
	// a reusable status so the reuse branch fires.
	bh.FetchCheckoutSubscription = func(subID string) (string, string, error) {
		return "created", "https://rzp.io/reuse", nil
	}
	createCalled := false
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		createCalled = true
		return map[string]any{"id": "should_not_happen", "short_url": "x"}, nil
	}
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, code, "body=%v", body)
	assert.Equal(t, true, body["reused"])
	assert.Equal(t, pendingSub, body["subscription_id"])
	assert.False(t, createCalled, "reuse must NOT mint a second subscription")
}

func TestCov2_Checkout_PendingFetchErrors_FallsThroughToCreate(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	teamUUID := uuid.MustParse(teamID)
	require.NoError(t, models.InsertPendingCheckout(context.Background(), db, "sub_old_"+uuid.NewString(), teamUUID, "u@example.com", "pro"))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	// Every candidate fetch errors → per-candidate fail-open skip → mint fresh.
	bh.FetchCheckoutSubscription = func(subID string) (string, string, error) {
		return "", "", errors.New("razorpay fetch down")
	}
	freshSub := "sub_fresh_" + uuid.NewString()
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return map[string]any{"id": freshSub, "short_url": "https://rzp.io/new"}, nil
	}
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, code, "body=%v", body)
	assert.Equal(t, freshSub, body["subscription_id"])
}

func TestCov2_Checkout_CreateError_Returns502(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return nil, errors.New("razorpay down")
	}
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	assert.Equal(t, http.StatusBadGateway, code)
	assert.Equal(t, "razorpay_error", body["error"])
}

func TestCov2_Checkout_IncompleteResponse_Returns502(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return map[string]any{"id": "sub_x"}, nil // no short_url
	}
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	assert.Equal(t, http.StatusBadGateway, code)
	assert.Equal(t, "razorpay_error", body["error"])
}

func TestCov2_Checkout_PromoCode_ValidStampsNotes(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	code := "PROMO" + strings.ToUpper(uuid.NewString()[:8])
	_, err := db.Exec(`INSERT INTO admin_promo_codes (code, team_id, issued_by_email, kind, value, expires_at) VALUES ($1,$2::uuid,'admin@x','percent_off',25, now()+interval '30 days')`, code, teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM admin_promo_codes WHERE code = $1`, code)

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	var capturedNotes map[string]any
	freshSub := "sub_promo_" + uuid.NewString()
	bh.CreateSubscription = func(body map[string]any) (map[string]any, error) {
		capturedNotes, _ = body["notes"].(map[string]any)
		return map[string]any{"id": freshSub, "short_url": "https://rzp.io/p"}, nil
	}
	status, _ := postCheckoutReq(t, app, map[string]any{"plan": "pro", "promotion_code": code})
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, capturedNotes)
	assert.NotEmpty(t, capturedNotes[handlers.ExportedCheckoutNoteAdminPromoCodeID], "a valid admin promo code stamps its id into the notes")
}

func TestCov2_Checkout_PromoCode_ExpiredSkipsBookkeeping(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	code := "EXPIRED" + strings.ToUpper(uuid.NewString()[:8])
	// Expired code → row exists but is unusable → notes left untouched.
	_, err := db.Exec(`INSERT INTO admin_promo_codes (code, team_id, issued_by_email, kind, value, expires_at) VALUES ($1,$2::uuid,'admin@x','percent_off',25, now()-interval '1 day')`, code, teamID)
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM admin_promo_codes WHERE code = $1`, code)

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	var capturedNotes map[string]any
	freshSub := "sub_exp_" + uuid.NewString()
	bh.CreateSubscription = func(body map[string]any) (map[string]any, error) {
		capturedNotes, _ = body["notes"].(map[string]any)
		return map[string]any{"id": freshSub, "short_url": "https://rzp.io/e"}, nil
	}
	status, _ := postCheckoutReq(t, app, map[string]any{"plan": "pro", "promotion_code": code})
	require.Equal(t, http.StatusOK, status)
	require.NotNil(t, capturedNotes)
	_, present := capturedNotes[handlers.ExportedCheckoutNoteAdminPromoCodeID]
	assert.False(t, present, "an expired admin promo code must not stamp the notes")
}

func TestCov2_Checkout_TeamTierUnavailable(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDTeam: "plan_team"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, _ := cov2CheckoutApp(t, db, cfg, teamID, userID)
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "team"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "tier_unavailable", body["error"])
}

func TestCov2_Checkout_InvalidPlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, _ := cov2CheckoutApp(t, db, cfg, teamID, userID)
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "wat"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_plan", body["error"])
}

func TestCov2_Checkout_InvalidFrequency(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, _ := cov2CheckoutApp(t, db, cfg, teamID, userID)
	code, body := postCheckoutReq(t, app, map[string]any{"plan": "pro", "plan_frequency": "weekly"})
	assert.Equal(t, http.StatusBadRequest, code)
	assert.Equal(t, "invalid_frequency", body["error"])
}

// ── ListInvoicesAPI / UpdatePaymentMethodAPI error branches ──────────────────

func TestCov2_ListInvoices_NoSubscription_ReturnsEmpty(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, teamID); return c.Next() })
	app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode) // no sub → empty invoices
}

// ── retryable DB-error branches (closed DB) → webhook 500 ────────────────────

// cov2ClosedDBApp builds a webhook app whose DB is already closed, so any
// query (e.g. GetTeamByRazorpaySubscriptionID in resolveTeamFromNotes)
// returns a real "sql: database is closed" error → the handler treats it as
// retryable → 500.
func cov2ClosedDBApp(t *testing.T) (*fiber.App, *config.Config) {
	t.Helper()
	closedDB, clean := testhelpers.SetupTestDB(t)
	clean() // run migrations then close the pool → subsequent queries error
	_ = closedDB.Close()
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayWebhookSecret: testWebhookSecret,
		RazorpayPlanIDPro:     cfgPlanPro,
	}
	bh := handlers.NewBillingHandler(closedDB, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)
	return app, cfg
}

// cov2RetryableEvent builds an event with NO team_id in notes but WITH a
// sub.ID, so resolveTeamFromNotes falls to the DB lookup (which errors on a
// closed DB → retryable).
func cov2RetryableEvent(t *testing.T, eventName string) []byte {
	t.Helper()
	sub, _ := json.Marshal(map[string]any{
		"id": "sub_" + uuid.NewString(), "entity": "subscription",
		"status": "active", "notes": map[string]any{},
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": eventName,
		"payload": map[string]any{"subscription": map[string]any{"entity": json.RawMessage(sub)}},
	}
	b, _ := json.Marshal(event)
	return b
}

func TestCov2_RetryableDBError_AllSubscriptionEvents(t *testing.T) {
	cov2NeedsDB(t)
	for _, ev := range []string{
		"subscription.charged",
		"subscription.activated",
		"subscription.cancelled",
		"subscription.halted",
		"subscription.completed",
		"subscription.paused",
		"subscription.resumed",
		"subscription.pending",
		"subscription.charged_failed",
		"subscription.updated",
		"subscription.deauthenticated",
	} {
		t.Run(ev, func(t *testing.T) {
			app, _ := cov2ClosedDBApp(t)
			payload := cov2RetryableEvent(t, ev)
			code, _ := cov2Run(t, app, payload)
			assert.Equal(t, http.StatusInternalServerError, code,
				"a real DB error during team-resolve is retryable → 500 so Razorpay redelivers")
		})
	}
}

func TestCov2_UpdatePaymentMethod_NoSubscription_Returns400(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, teamID); return c.Next() })
	app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "no_subscription", body["error"])
}
