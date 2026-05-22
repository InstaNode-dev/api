package handlers_test

// billing_coverage3_test.go — third-wave coverage: the production default
// closures in NewBillingHandler, the planIDToTier tier matrix (growth /
// team-yearly / hobby-yearly / unknown), requireVerifiedEmail fail-open
// branches, and the sendPaymentReceipt payment-id-fallback dedup path.

import (
	"bytes"
	"context"
	"database/sql"
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
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// TestCov3_NewBillingHandler_DefaultClosures executes the three prod default
// closures NewBillingHandler wires. With garbage Razorpay creds they error
// (or trip the breaker); we only assert no panic — the point is line
// coverage of the closure bodies.
func TestCov3_NewBillingHandler_DefaultClosures(t *testing.T) {
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_garbage",
		RazorpayKeySecret: "garbage_secret",
	}
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	// Each Exercise* recovers internally; the assertions are just "did not
	// hang / panic out of the test".
	handlers.ExerciseFetchSubscriptionDetails(bh, "sub_does_not_exist")
	handlers.ExerciseCreateSubscription(bh)
	handlers.ExerciseFetchCheckoutSubscription(bh, "sub_does_not_exist")
}

// TestCov3_PlanIDToTier_Matrix walks every configured tier (incl. yearly
// variants + growth) so the per-branch comparisons in planIDToTier are all
// exercised, plus the empty + unknown fallback branches.
func TestCov3_PlanIDToTier_Matrix(t *testing.T) {
	cfg := &config.Config{
		RazorpayPlanIDHobby:           "h_m",
		RazorpayPlanIDHobbyYearly:     "h_y",
		RazorpayPlanIDHobbyPlus:       "hp_m",
		RazorpayPlanIDHobbyPlusYearly: "hp_y",
		RazorpayPlanIDPro:             "p_m",
		RazorpayPlanIDProYearly:       "p_y",
		RazorpayPlanIDGrowth:          "g_m",
		RazorpayPlanIDGrowthYearly:    "g_y",
		RazorpayPlanIDTeam:            "t_m",
		RazorpayPlanIDTeamYearly:      "t_y",
	}
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	cases := map[string]string{
		"t_m":      "team",
		"t_y":      "team",
		"g_m":      "growth",
		"g_y":      "growth",
		"p_m":      "pro",
		"p_y":      "pro",
		"hp_m":     "hobby_plus",
		"hp_y":     "hobby_plus",
		"h_m":      "hobby",
		"h_y":      "hobby",
		"":         handlers.PlanIDToTierFallbackForTest, // empty → fallback
		"bogus_id": handlers.PlanIDToTierFallbackForTest, // unknown → fallback
	}
	for planID, want := range cases {
		assert.Equal(t, want, handlers.ExportedPlanIDToTier(bh, planID), "plan_id=%q", planID)
	}
}

// ── requireVerifiedEmail fail-open branches (via CreateCheckoutAPI) ──────────

// cov3CheckoutApp wires CreateCheckoutAPI stamping the given (teamID, userID)
// locals. userID="" exercises the no-user-id fail-open; a non-UUID userID
// exercises the bad-user-id fail-open.
func cov3CheckoutApp(t *testing.T, db *sql.DB, cfg *config.Config, teamID, userID string) *fiber.App {
	t.Helper()
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app
}

func cov3PostCheckout(t *testing.T, app *fiber.App) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var rb map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&rb)
	return resp.StatusCode, rb
}

func TestCov3_RequireVerifiedEmail_NoUserID_FailsOpen(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!"} // no Razorpay → 503 after gate
	app := cov3CheckoutApp(t, db, cfg, teamID, "")                                   // no user id
	code, body := cov3PostCheckout(t, app)
	// Gate fails open (no user id) → proceeds → 503 billing_not_configured.
	assert.NotEqual(t, http.StatusForbidden, code)
	assert.NotEqual(t, "email_not_verified", body["error"])
}

func TestCov3_RequireVerifiedEmail_BadUserID_FailsOpen(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!"}
	app := cov3CheckoutApp(t, db, cfg, teamID, "not-a-uuid") // bad user id → parse fail-open
	code, body := cov3PostCheckout(t, app)
	assert.NotEqual(t, http.StatusForbidden, code)
	assert.NotEqual(t, "email_not_verified", body["error"])
}

func TestCov3_RequireVerifiedEmail_UserLookupError_FailsOpen(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	clean() // close pool → GetUserByID errors → fail-open
	_ = db.Close()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!"}
	app := cov3CheckoutApp(t, db, cfg, uuid.NewString(), uuid.NewString())
	code, body := cov3PostCheckout(t, app)
	assert.NotEqual(t, http.StatusForbidden, code)
	assert.NotEqual(t, "email_not_verified", body["error"])
}

// ── ListInvoices / UpdatePayment / ChangePlan with a stored subscription ─────
// (the Razorpay call then fails on garbage creds → error branches)

func cov3SeedTeamWithSub(t *testing.T, db *sql.DB, tier string) string {
	t.Helper()
	teamID := testhelpers.MustCreateTeamDB(t, db, tier)
	require.NoError(t, models.UpdateRazorpaySubscriptionID(context.Background(), db, uuid.MustParse(teamID), "sub_"+uuid.NewString()))
	t.Cleanup(func() { db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID) })
	return teamID
}

func TestCov3_ListInvoices_WithSub_RazorpayError(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := cov3SeedTeamWithSub(t, db, "pro")
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "rzp_test_garbage", RazorpayKeySecret: "garbage"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, teamID); return c.Next() })
	app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// A live subscription → the Razorpay list call fires and fails (garbage
	// creds / circuit) → 502 or 503. Either way it's not the empty-200 path.
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusServiceUnavailable}, resp.StatusCode)
}

func TestCov3_UpdatePayment_WithSub_Error(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := cov3SeedTeamWithSub(t, db, "pro")
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "rzp_test_garbage", RazorpayKeySecret: "garbage"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, teamID); return c.Next() })
	app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil)
	resp, err := app.Test(req, 10000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Contains(t, []int{http.StatusUnprocessableEntity, http.StatusServiceUnavailable}, resp.StatusCode)
}

func TestCov3_ChangePlan_WithSub_UpgradeRazorpayError(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := cov3SeedTeamWithSub(t, db, "hobby")
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "rzp_test_garbage", RazorpayKeySecret: "garbage", RazorpayPlanIDHobby: "plan_hobby", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, teamID)
	// hobby → pro upgrade, subscription present → ChangePlan calls Razorpay,
	// which fails on garbage creds → 502 razorpay_error or 503 circuit.
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Contains(t, []int{http.StatusBadGateway, http.StatusServiceUnavailable}, code, "body=%v", body)
}

// ── sendPaymentReceipt: payment-id fallback dedup key (no paid_count) ────────

// TestCov3_Charged_NoOwner_ReceiptSkipped covers sendPaymentReceipt's
// no-owner-email early return (team has no users).
func TestCov3_Charged_NoOwner_ReceiptSkipped(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, cfg := cov2WebhookAppReal(t, db, email.NewNoop())
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	// No user created → sendPaymentReceipt logs receipt_no_email + returns.
	paid := 1
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", &paid, 490000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
}

// TestCov3_Webhook_NoEventID covers the eventID=="" branch (no
// X-Razorpay-Event-Id header and no body id) — logs no_event_id, proceeds.
func TestCov3_Webhook_NoEventID(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	// An event with NO top-level id field and an unhandled event type → the
	// no_event_id branch + default case both run, returning 200.
	event := map[string]any{
		"entity": "event", "event": "order.paid", "payload": map[string]any{},
	}
	b, _ := json.Marshal(event)
	req := signedWebhookRequest(t, b)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCov3_PaymentFailed_MalformedEntity covers handlePaymentFailed's JSON
// unmarshal-error early return (non-retryable → 200).
func TestCov3_PaymentFailed_MalformedEntity(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": "not-json"}},
	}
	b, _ := json.Marshal(event)
	req := signedWebhookRequest(t, b)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCov3_ChangePlan_UnverifiedEmail_Returns403 covers the requireVerifiedEmail
// gate firing inside ChangePlanAPI (a user with email_verified=false).
func TestCov3_ChangePlan_UnverifiedEmail_Returns403(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	u, err := models.CreateUser(context.Background(), db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err) // email_verified=false by default
	defer db.Exec(`DELETE FROM users WHERE id = $1`, u.ID)

	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, u.ID.String())
		return c.Next()
	})
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)

	b, _ := json.Marshal(map[string]any{"target_plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "email_not_verified", body["error"])
}

// TestCov3_ChangePlan_DBError covers ChangePlanAPI's db_error branch when the
// SELECT plan_tier query fails (closed DB).
func TestCov3_ChangePlan_DBError(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	clean()
	_ = db.Close()
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s", RazorpayPlanIDPro: "plan_pro"}
	app := changePlanAppReal(t, db, cfg, uuid.NewString())
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, "db_error", body["error"])
}

// TestCov3_Checkout_Unauthorized covers CreateCheckoutAPI's bad-team-id 401.
func TestCov3_Checkout_Unauthorized(t *testing.T) {
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!", RazorpayKeyID: "k", RazorpayKeySecret: "s"}
	bh := handlers.NewBillingHandler(nil, cfg, email.NewNoop())
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, "not-a-uuid"); return c.Next() })
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// ── audit-emit DB-failure branches (closed DB) ───────────────────────────────

// TestCov3_AuditEmits_DBClosed_FailOpen drives every best-effort audit emit
// against a closed DB so the InsertAuditEvent-failed slog.Warn branch is
// covered. None must panic.
func TestCov3_AuditEmits_DBClosed_FailOpen(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	clean()
	_ = db.Close()
	ctx := context.Background()
	team := uuid.New()
	handlers.ExportedEmitSubscriptionCanceledAudit(ctx, db, team, "pro", "hobby", "sub_x")
	handlers.ExportedEmitSubscriptionCanceledAudit(ctx, db, team, "pro", "free", "sub_x") // free-summary branch
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, team, "hobby", "pro", "sub_x")  // upgrade
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, team, "pro", "hobby", "sub_x")  // downgrade
	handlers.ExportedEmitPaymentGraceRecoveredAudit(ctx, db, team, "sub_x")
	handlers.ExportedEmitPaymentGraceStartedAudit(ctx, db, team, "sub_x", 0)      // amount unknown
	handlers.ExportedEmitPaymentGraceStartedAudit(ctx, db, team, "sub_x", 490000) // amount known
	handlers.ExportedEmitChargeUndeliverableAudit(ctx, db, team, "sub_x", "plan_x", "team_unresolvable", "")
	handlers.ExportedEmitChargeUndeliverableAudit(ctx, db, team, "sub_x", "plan_x", "unknown_tier", "pro") // resolvedTier set
}

// TestCov3_MaybeRecoverPaymentGrace_Branches drives nil-db, lookup-error
// (closed db), no-active-grace, and the happy flip + already-recovered paths.
func TestCov3_MaybeRecoverPaymentGrace_Branches(t *testing.T) {
	cov2NeedsDB(t)
	ctx := context.Background()

	// nil db → early return.
	handlers.ExportedMaybeRecoverPaymentGrace(ctx, nil, uuid.New(), "sub_x")

	// uuid.Nil team → early return.
	live, cleanLive := testhelpers.SetupTestDB(t)
	handlers.ExportedMaybeRecoverPaymentGrace(ctx, live, uuid.Nil, "sub_x")

	// no active grace → GetActivePaymentGracePeriod returns nil → early return.
	teamID := testhelpers.MustCreateTeamDB(t, live, "pro")
	teamUUID := uuid.MustParse(teamID)
	handlers.ExportedMaybeRecoverPaymentGrace(ctx, live, teamUUID, "sub_none")

	// active grace present → flip to recovered (happy path).
	require.NoError(t, startGraceForTest(t, live, teamUUID, "sub_grace"))
	handlers.ExportedMaybeRecoverPaymentGrace(ctx, live, teamUUID, "sub_grace")
	var status string
	require.NoError(t, live.QueryRow(`SELECT status FROM payment_grace_periods WHERE team_id = $1::uuid ORDER BY started_at DESC LIMIT 1`, teamID).Scan(&status))
	assert.Equal(t, "recovered", status)
	live.Exec(`DELETE FROM payment_grace_periods WHERE team_id = $1::uuid`, teamID)
	live.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	cleanLive()

	// lookup error → closed db.
	closed, cleanClosed := testhelpers.SetupTestDB(t)
	cleanClosed()
	_ = closed.Close()
	handlers.ExportedMaybeRecoverPaymentGrace(ctx, closed, uuid.New(), "sub_x")
}

// TestCov3_AuditEmits_NilTeam covers the uuid.Nil + no-resolved-tier paths in
// emitChargeUndeliverableAudit and emitSubscriptionChangeAudit's no-op guard
// (same-tier / unknown tier → no insert) against a live DB.
func TestCov3_AuditEmits_NilTeamAndNoop(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	ctx := context.Background()
	// same-tier → emitSubscriptionChangeAudit returns without inserting.
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, uuid.New(), "pro", "pro", "sub_x")
	// unknown tier (-1 rank) → no-op.
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, uuid.New(), "bogus", "pro", "sub_x")
	// charge-undeliverable with uuid.Nil team (stored as NULL) — live insert.
	handlers.ExportedEmitChargeUndeliverableAudit(ctx, db, uuid.Nil, "sub_x", "plan_x", "team_unresolvable", "")
}

// TestCov3_EmitSubscriptionChangeAudit_DedupSkipsSecond covers the F9
// idempotency guard: a second emit for the same (team, kind, sub) is skipped.
func TestCov3_EmitSubscriptionChangeAudit_DedupSkipsSecond(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")
	defer db.Exec(`DELETE FROM teams WHERE id = $1::uuid`, teamID)
	defer db.Exec(`DELETE FROM audit_log WHERE team_id = $1::uuid`, teamID)
	teamUUID := uuid.MustParse(teamID)
	ctx := context.Background()
	subID := "sub_" + uuid.NewString()
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, teamUUID, "hobby", "pro", subID)
	handlers.ExportedEmitSubscriptionChangeAudit(ctx, db, teamUUID, "hobby", "pro", subID) // deduped
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM audit_log WHERE team_id = $1::uuid AND kind = 'subscription.upgraded'`, teamID).Scan(&n))
	assert.Equal(t, 1, n, "the F9 guard suppresses a duplicate change-audit row")
}

// TestCov3_PaymentFailed_OnlyOrderID_Drops covers resolveTeamFromPayment
// returning uuid.Nil (only an order_id, which is not yet wired) → email
// dropped → 200.
func TestCov3_PaymentFailed_OnlyOrderID_Drops(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	app, _ := cov2WebhookAppReal(t, db, email.NewNoop())
	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
		"order_id": "order_" + uuid.NewString(), // only order_id → unresolvable
	})
	event := map[string]any{
		"entity": "event", "id": "evt_" + uuid.NewString(), "event": "payment.failed",
		"payload": map[string]any{"payment": map[string]any{"entity": json.RawMessage(payEntity)}},
	}
	b, _ := json.Marshal(event)
	req := signedWebhookRequest(t, b)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestCov3_PaymentFailed_SiblingSubID_DBLookup covers resolveTeamFromPayment
// path 3-by-id: a sibling subscription with NO team_id in notes but a sub.ID
// that maps to a team via the DB.
func TestCov3_PaymentFailed_SiblingSubID_DBLookup(t *testing.T) {
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

	subEntity, _ := json.Marshal(map[string]any{
		"id": subID, "entity": "subscription", "notes": map[string]any{}, // no team_id
	})
	payEntity, _ := json.Marshal(map[string]any{
		"id": "pay_" + uuid.NewString(), "entity": "payment",
		"amount": 490000, "currency": "INR", "attempt_count": 1,
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

// TestCov3_Charged_NoPaymentEntity_ReceiptAmountUnknown covers
// chargedPaymentMeta's nil-payment return + sendPaymentReceipt's
// AmountKnown=false path: a charged event with an owner + paid_count but NO
// payment entity.
func TestCov3_Charged_NoPaymentEntity_ReceiptAmountUnknown(t *testing.T) {
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
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)
	paid := 1
	// paymentAmount=0 → no payment entity bundled → chargedPaymentMeta nil path.
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", &paid, 0)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
}

// TestCov3_Charged_ReceiptDeduped covers sendPaymentReceipt's pre-claimed
// dedup-skip path: the receipt key for this billing cycle is already claimed,
// so the receipt send is skipped.
func TestCov3_Charged_ReceiptDeduped(t *testing.T) {
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
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)

	subID := "sub_" + uuid.NewString()
	paid := 2
	// Pre-claim the receipt key (sub+paid_count) so the handler's claim
	// returns already-used → receipt_deduped early return.
	receiptKey := "receipt:" + subID + ":paid:2"
	claimed, err := models.ClaimEmailSend(context.Background(), db, receiptKey, models.EmailSendKindReceipt)
	require.NoError(t, err)
	require.True(t, claimed)

	payload := cov2SubEvent(t, "subscription.charged", teamID, subID, cfg.RazorpayPlanIDPro, "active", &paid, 490000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)
}

func TestCov3_Charged_WithOwner_NoPaidCount_PaymentIDDedup(t *testing.T) {
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
	defer db.Exec(`DELETE FROM email_send_dedup WHERE 1=1`)

	// charged with a payment entity (amount + id) but NO paid_count →
	// receiptDedupKey falls back to the "receipt:<sub>:pay:<paymentID>" form.
	payload := cov2SubEvent(t, "subscription.charged", teamID, "sub_"+uuid.NewString(), cfg.RazorpayPlanIDPro, "active", nil, 490000)
	code, _ := cov2Run(t, app, payload)
	require.Equal(t, http.StatusOK, code)

	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1::uuid`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
}
