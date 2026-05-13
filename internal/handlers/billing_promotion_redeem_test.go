package handlers_test

// billing_promotion_redeem_test.go — covers the admin-code fallback inside
// POST /api/v1/billing/promotion/validate and the
// subscription.charged → admin_promo_codes.used_at redemption hook.
//
// Layered on top of billing_promotion_test.go (which exercises the
// plans-yaml-only path with a nil DB). These tests require TEST_DATABASE_URL
// because the admin-code path is purely DB-driven.
//
// Test surface:
//
//   1) Admin-issued code that exists + unused + not expired → 200 + ok:true
//      with discount shape carrying the admin code's kind/value.
//   2) Admin code with used_at NOT NULL → 200 + ok:false +
//      promotion_already_used + AgentActionPromotionAlreadyUsed.
//   3) Admin code with expires_at in the past → 200 + ok:false +
//      promotion_expired + AgentActionPromotionExpired.
//   4) Admin code that belongs to a different team → 200 + ok:false +
//      promotion_invalid (we don't reveal cross-team codes exist).
//   5) Webhook subscription.charged with notes.admin_promo_code_id → marks
//      admin_promo_codes.used_at.
//   6) Webhook subscription.charged WITHOUT notes.admin_promo_code_id → no
//      admin_promo_codes side-effect (regression-safe).
//   7) Plans-yaml code happy path still works when DB is wired (regression
//      for PR #47 — the plans-yaml branch must not fall through to admin
//      lookup when the registry finds the code).
//
// Note on "wrong plan" for admin codes: admin_promo_codes.applies_to is
// INTEGER (a percent-off cap in cents per openapi.go), NOT a list of
// applicable tiers. Admin codes are scoped to a team_id, not a plan, so
// the handler does not reject the validate request based on the requested
// plan — the discount.applies_to field echoes the requested plan back so
// the dashboard renders "applies to <plan>" uniformly. The brief's
// "wrong plan → promotion_invalid" item assumed plan-applicability that
// the migration 021 schema does not carry; that divergence is documented
// in the final PR description.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// adminRedeemNeedsDB skips when no TEST_DATABASE_URL is configured. The
// admin-code path is purely DB-driven so there's no value in running these
// tests without a real test Postgres.
func adminRedeemNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("admin-redeem tests: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// adminRedeemRegistry loads a small plans.yaml fragment so the plans-yaml
// happy path can be regression-tested alongside the admin-code path.
// Mirrors promoTestYAML in billing_promotion_test.go but kept local so the
// two files can evolve independently.
func adminRedeemRegistry(t *testing.T) *plans.Registry {
	t.Helper()
	const yamlBody = `
plans:
  anonymous:
    display_name: "Anonymous"
    price_monthly_cents: 0
    trial_days: 0
    limits: { provisions_per_day: 5 }
    features: {}
  hobby:
    display_name: "Hobby"
    price_monthly_cents: 900
    trial_days: 0
    limits: { provisions_per_day: 50 }
    features: {}
  pro:
    display_name: "Pro"
    price_monthly_cents: 4900
    trial_days: 0
    limits: { provisions_per_day: 500 }
    features: {}
  team:
    display_name: "Team"
    price_monthly_cents: 19900
    trial_days: 0
    limits: { provisions_per_day: 5000 }
    features: {}

promotions:
  - code: "TWITTER15"
    discount_percent: 15
    applies_to: ["pro", "team"]
    expires_at: "2099-12-31"
    max_uses: -1
    description: "15% off Pro or Team — Twitter promotion"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "plans.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yamlBody), 0o600))
	reg, err := plans.Load(path)
	require.NoError(t, err)
	return reg
}

// adminRedeemApp builds the Fiber app for promotion-validate tests with both
// a real DB (so admin-code fallback works) and miniredis. teamID is seeded
// into c.Locals so the rate-limit + admin lookup scopes match a real
// authenticated session.
func adminRedeemApp(t *testing.T, db *sql.DB, teamID uuid.UUID) *fiber.App {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	reg := adminRedeemRegistry(t)

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		return c.Next()
	})
	h := handlers.NewBillingPromotionHandler(db, rdb, reg)
	app.Post("/api/v1/billing/promotion/validate", h.ValidatePromotion)
	return app
}

// postAdminRedeem posts a body and returns (status, parsed JSON).
func postAdminRedeem(t *testing.T, app *fiber.App, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	if resp.ContentLength != 0 {
		_ = json.NewDecoder(resp.Body).Decode(&out)
	}
	return resp.StatusCode, out
}

// seedAdminCode inserts an admin_promo_codes row with the supplied values
// and returns the persisted code + id. Callers can flip used_at / expires_at
// on the returned row before validating. Caller is responsible for cleanup
// (registered as t.Cleanup).
func seedAdminCode(t *testing.T, db *sql.DB, teamID uuid.UUID, opts adminCodeOpts) (string, uuid.UUID) {
	t.Helper()
	if opts.Kind == "" {
		opts.Kind = models.PromoKindPercentOff
	}
	if opts.Value == 0 {
		opts.Value = 25
	}
	if opts.ExpiresAt.IsZero() {
		opts.ExpiresAt = time.Now().UTC().Add(30 * 24 * time.Hour)
	}
	if opts.Code == "" {
		// Codes are stored UPPER in the table (the production issuance path
		// uppercases via generatePromoCode); the validate handler uppercases
		// on lookup. Mirror that here so the seeded code round-trips.
		opts.Code = strings.ToUpper("TEST" + uuid.NewString()[:4])
	}

	var id uuid.UUID
	var usedAt interface{}
	if opts.UsedAt != nil {
		usedAt = *opts.UsedAt
	}

	err := db.QueryRowContext(context.Background(), `
		INSERT INTO admin_promo_codes
		    (code, team_id, issued_by_email, kind, value, expires_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`, opts.Code, teamID, "admin@instanode.dev", opts.Kind, opts.Value, opts.ExpiresAt, usedAt).Scan(&id)
	require.NoError(t, err, "seedAdminCode: insert failed")

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM admin_promo_codes WHERE id = $1`, id)
	})
	return opts.Code, id
}

type adminCodeOpts struct {
	Code      string
	Kind      string
	Value     int
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// ── Tests ────────────────────────────────────────────────────────────────────

// TestValidatePromotion_AdminCode_Unused_ReturnsDiscount — happy path for an
// admin-issued, unused, unexpired code. Asserts the response shape matches
// the plans-yaml branch so the dashboard renders both source paths
// uniformly.
func TestValidatePromotion_AdminCode_Unused_ReturnsDiscount(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	code, _ := seedAdminCode(t, db, teamID, adminCodeOpts{Kind: models.PromoKindPercentOff, Value: 40})

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["ok"], "admin code should validate; body=%v", body)
	assert.Equal(t, code, body["code"])
	discount, ok := body["discount"].(map[string]any)
	require.True(t, ok, "discount must be populated on happy path; body=%v", body)
	assert.Equal(t, "percent_off", discount["kind"])
	assert.Equal(t, float64(40), discount["value"])
	assert.Equal(t, float64(1), discount["max_uses"], "admin codes are single-use")
	appliesTo, ok := discount["applies_to"].([]any)
	require.True(t, ok)
	// Admin codes apply to any plan the team chooses; we echo the requested
	// plan back so the dashboard renders "applies to pro".
	assert.Contains(t, appliesTo, "pro")
}

// TestValidatePromotion_AdminCode_AmountOff_MapsCorrectly — admin codes can
// carry kind=amount_off (cents). Asserts the mapping flows through the
// discount.kind/value channel verbatim so dashboard / MCP clients can
// branch on kind.
func TestValidatePromotion_AdminCode_AmountOff_MapsCorrectly(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	code, _ := seedAdminCode(t, db, teamID, adminCodeOpts{Kind: models.PromoKindAmountOff, Value: 5000})

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"])
	discount := body["discount"].(map[string]any)
	assert.Equal(t, "amount_off", discount["kind"], "amount_off kind must round-trip to the response")
	assert.Equal(t, float64(5000), discount["value"])
	assert.Contains(t, discount["description"], "off")
}

// TestValidatePromotion_AdminCode_FirstMonthFree_MapsCorrectly — first-month-free
// kind is the third admin variant. Same round-trip assertion as
// amount_off so a future change to the kind enum is caught.
func TestValidatePromotion_AdminCode_FirstMonthFree_MapsCorrectly(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	code, _ := seedAdminCode(t, db, teamID, adminCodeOpts{Kind: models.PromoKindFirstMonthFree, Value: 0})

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["ok"])
	discount := body["discount"].(map[string]any)
	assert.Equal(t, "first_month_free", discount["kind"])
	assert.Contains(t, discount["description"], "First month free")
}

// TestValidatePromotion_AdminCode_AlreadyUsed_ReturnsOkFalse — used_at
// non-null must surface promotion_already_used + the distinct
// AgentActionPromotionAlreadyUsed sentence. The wall is friendlier than
// "promotion_invalid" because the remedy ("ask for a fresh code") differs.
func TestValidatePromotion_AdminCode_AlreadyUsed_ReturnsOkFalse(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	usedAt := time.Now().UTC().Add(-1 * time.Hour)
	code, _ := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:   models.PromoKindPercentOff,
		Value:  20,
		UsedAt: &usedAt,
	})

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status, "200 + ok:false envelope, not 4xx; body=%v", body)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_already_used", body["error"])
	assert.Equal(t, handlers.AgentActionPromotionAlreadyUsed, body["agent_action"],
		"must surface the distinct already-used agent_action, not the generic promotion_invalid one")
	assert.Nil(t, body["discount"])
}

// TestValidatePromotion_AdminCode_Expired_ReturnsExpired — expires_at in
// the past surfaces promotion_expired + AgentActionPromotionExpired (NOT
// promotion_invalid).
func TestValidatePromotion_AdminCode_Expired_ReturnsExpired(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	code, _ := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:      models.PromoKindPercentOff,
		Value:     20,
		ExpiresAt: time.Now().UTC().Add(-24 * time.Hour),
	})

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_expired", body["error"])
	assert.Equal(t, handlers.AgentActionPromotionExpired, body["agent_action"])
}

// TestValidatePromotion_AdminCode_DifferentTeam_RevealsNothing — a code
// issued to team A must surface as promotion_invalid (NOT promotion_*
// anything-else) when team B tries to validate it. We deliberately don't
// reveal cross-team codes exist — that would be an information disclosure
// (e.g. "this code belongs to a different team" leaks the existence of
// the row).
func TestValidatePromotion_AdminCode_DifferentTeam_RevealsNothing(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamA := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	teamB := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id IN ($1, $2)`, teamA, teamB)

	// Issue code to team A.
	code, _ := seedAdminCode(t, db, teamA, adminCodeOpts{Kind: models.PromoKindPercentOff, Value: 25})

	// Team B tries to validate it.
	app := adminRedeemApp(t, db, teamB)
	status, body := postAdminRedeem(t, app, map[string]string{"code": code, "plan": "pro"})

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["ok"], "cross-team codes must NOT validate; body=%v", body)
	// Surfaces as plain "invalid" (same as an unknown code) so we don't
	// disclose that a row exists.
	assert.Equal(t, "promotion_invalid", body["error"])
}

// TestValidatePromotion_PlansYamlCode_StillWorks — regression for PR #47.
// With the DB wired in, plans-yaml codes must still take the plans-yaml
// branch and never fall through to the admin lookup. We confirm by asserting
// the discount payload matches the YAML registry's shape (max_uses=-1 from
// the YAML, not 1 from the admin-code synthesizer).
func TestValidatePromotion_PlansYamlCode_StillWorks(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	app := adminRedeemApp(t, db, teamID)
	status, body := postAdminRedeem(t, app, map[string]string{"code": "TWITTER15", "plan": "pro"})

	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "TWITTER15", body["code"])
	discount := body["discount"].(map[string]any)
	assert.Equal(t, "percent_off", discount["kind"])
	assert.Equal(t, float64(15), discount["value"])
	// PR #47's plans-yaml shape: max_uses=-1 here, NOT the single-use=1
	// of the admin-code synthesizer. This asserts the dispatcher correctly
	// kept this in the plans-yaml branch and never reached the admin code
	// fallback.
	assert.Equal(t, float64(-1), discount["max_uses"])
}

// TestValidatePromotion_PlansYamlWrongPlan_DoesNotFallThroughToAdmin — a
// plans-yaml code that doesn't apply to the requested plan must NOT be
// re-tried as an admin code. The classifier already returns
// "promotion_invalid" with the plans-yaml wording; falling through would
// produce stale "this code has expired" wording or worse.
func TestValidatePromotion_PlansYamlWrongPlan_DoesNotFallThroughToAdmin(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	app := adminRedeemApp(t, db, teamID)
	// TWITTER15 applies to pro/team but not hobby.
	status, body := postAdminRedeem(t, app, map[string]string{"code": "TWITTER15", "plan": "hobby"})

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["ok"])
	assert.Equal(t, "promotion_invalid", body["error"])
	assert.Contains(t, body["message"], "hobby",
		"wrong-plan response must name the requested plan in the message")
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook redemption hook
// ─────────────────────────────────────────────────────────────────────────────

// makeChargedWithNotes builds a subscription.charged payload with an
// arbitrary notes map. Mirrors makeSubscriptionChargedPayload (in
// billing_test.go) but lets us inject admin_promo_code_id without a custom
// per-test struct.
func makeChargedWithNotes(t *testing.T, subscriptionID, planID string, notes map[string]string) []byte {
	t.Helper()
	notesAny := map[string]any{}
	for k, v := range notes {
		notesAny[k] = v
	}
	subEntity, _ := json.Marshal(map[string]any{
		"id":      subscriptionID,
		"entity":  "subscription",
		"plan_id": planID,
		"status":  "active",
		"notes":   notesAny,
	})
	event := map[string]any{
		"entity": "event",
		"event":  "subscription.charged",
		"payload": map[string]any{
			"subscription": map[string]any{
				"entity": json.RawMessage(subEntity),
			},
		},
	}
	payload, err := json.Marshal(event)
	require.NoError(t, err)
	return payload
}

// TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_MarksUsed —
// the redemption-on-activation contract. Notes carry the
// admin_promo_code_id stamped by CreateCheckoutAPI; the webhook must
// flip used_at = now() best-effort.
func TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_MarksUsed(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	_, promoID := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:  models.PromoKindPercentOff,
		Value: 50,
	})

	notes := map[string]string{
		"team_id":             teamID.String(),
		"admin_promo_code_id": promoID.String(),
	}
	payload := makeChargedWithNotes(t, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro, notes)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Assert the admin code row is now marked used.
	var usedAt sql.NullTime
	err = db.QueryRow(`SELECT used_at FROM admin_promo_codes WHERE id = $1`, promoID).Scan(&usedAt)
	require.NoError(t, err)
	assert.True(t, usedAt.Valid, "used_at must be set after subscription.charged with notes.admin_promo_code_id")
	assert.WithinDuration(t, time.Now(), usedAt.Time, 30*time.Second,
		"used_at should be set to ~now() (clock-skew tolerance: 30s)")
}

// TestBillingWebhook_SubscriptionCharged_NoAdminPromoCodeID_NoSideEffect —
// regression-safe contract: a webhook without notes.admin_promo_code_id
// must not touch admin_promo_codes for the team. Proves the redemption
// hook is gated on the notes key, not on the team_id alone.
func TestBillingWebhook_SubscriptionCharged_NoAdminPromoCodeID_NoSideEffect(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Seed an unused admin code that must stay unused.
	_, promoID := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:  models.PromoKindPercentOff,
		Value: 50,
	})

	// Charged webhook for the same team but no admin_promo_code_id in notes.
	notes := map[string]string{"team_id": teamID.String()}
	payload := makeChargedWithNotes(t, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro, notes)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Admin code must remain unused.
	var usedAt sql.NullTime
	err = db.QueryRow(`SELECT used_at FROM admin_promo_codes WHERE id = $1`, promoID).Scan(&usedAt)
	require.NoError(t, err)
	assert.False(t, usedAt.Valid, "used_at must remain NULL — webhook without notes.admin_promo_code_id is a no-op")
}

// TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_AlreadyUsed_NoOp —
// idempotent redelivery: a webhook arriving twice for the same subscription
// must not error and must not flip used_at a second time. The
// `WHERE used_at IS NULL` predicate in MarkAdminPromoCodeUsed enforces this;
// the test asserts the handler still returns 200 (Razorpay retries on
// non-2xx).
func TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_AlreadyUsed_NoOp(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	// Seed the code as already used.
	usedAt := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	_, promoID := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:   models.PromoKindPercentOff,
		Value:  50,
		UsedAt: &usedAt,
	})

	notes := map[string]string{
		"team_id":             teamID.String(),
		"admin_promo_code_id": promoID.String(),
	}
	payload := makeChargedWithNotes(t, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro, notes)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "redelivery must NOT 5xx — Razorpay would retry forever")

	// used_at must remain at its original value (the first-redemption time).
	var dbUsedAt sql.NullTime
	err = db.QueryRow(`SELECT used_at FROM admin_promo_codes WHERE id = $1`, promoID).Scan(&dbUsedAt)
	require.NoError(t, err)
	require.True(t, dbUsedAt.Valid)
	assert.WithinDuration(t, usedAt, dbUsedAt.Time, time.Second,
		"used_at must not be overwritten on redelivery")
}

// TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_Invalid_NoCrash —
// defensive: a malformed UUID in notes.admin_promo_code_id must not crash
// the handler or 5xx. The webhook still returns 200 (Razorpay retries
// otherwise) and the tier upgrade still lands.
func TestBillingWebhook_SubscriptionCharged_AdminPromoCodeID_Invalid_NoCrash(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	app, cfg := billingWebhookDBApp(t, db)

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	notes := map[string]string{
		"team_id":             teamID.String(),
		"admin_promo_code_id": "not-a-uuid",
	}
	payload := makeChargedWithNotes(t, "sub_test_"+uuid.NewString(), cfg.RazorpayPlanIDPro, notes)
	req := signedWebhookRequest(t, payload)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Tier still moved to pro — bad notes don't block the upgrade.
	var tier string
	require.NoError(t, db.QueryRow(`SELECT plan_tier FROM teams WHERE id = $1`, teamID).Scan(&tier))
	assert.Equal(t, "pro", tier)
}

// ─────────────────────────────────────────────────────────────────────────────
// Model-level concurrency sanity check
// ─────────────────────────────────────────────────────────────────────────────

// TestMarkAdminPromoCodeUsed_Race_OnlyOneWins exercises the single-use
// invariant at the model boundary: two concurrent UPDATE callers race;
// exactly one succeeds, the other gets ErrAdminPromoCodeAlreadyUsed.
// Catches the regression where a future refactor removes the
// `WHERE used_at IS NULL` predicate.
func TestMarkAdminPromoCodeUsed_Race_OnlyOneWins(t *testing.T) {
	db, cleanup := adminRedeemNeedsDB(t)
	defer cleanup()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)

	_, promoID := seedAdminCode(t, db, teamID, adminCodeOpts{
		Kind:  models.PromoKindPercentOff,
		Value: 50,
	})

	type result struct{ err error }
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			results <- result{err: models.MarkAdminPromoCodeUsed(context.Background(), db, promoID)}
		}()
	}

	wins := 0
	losses := 0
	for i := 0; i < 2; i++ {
		r := <-results
		switch {
		case r.err == nil:
			wins++
		case errors.Is(r.err, models.ErrAdminPromoCodeAlreadyUsed):
			losses++
		default:
			t.Fatalf("unexpected error from concurrent MarkAdminPromoCodeUsed: %v", r.err)
		}
	}
	assert.Equal(t, 1, wins, "exactly one caller must win the race")
	assert.Equal(t, 1, losses, "the loser must get ErrAdminPromoCodeAlreadyUsed")
}

// ─────────────────────────────────────────────────────────────────────────────
// /billing/checkout promo_code stamping
// ─────────────────────────────────────────────────────────────────────────────

// TestCheckout_PromotionCode_AdminIssued_StampsNotes — exercising the
// CreateCheckoutAPI promo-stamping branch end-to-end requires a Razorpay
// client we cannot reach in unit tests. So instead we directly hit
// /billing/checkout WITHOUT credentials (cfg.RazorpayKeyID="") and assert
// the lookup helper logic isn't bypassed by an early return. The actual
// notes write is covered indirectly via the webhook integration test.

// We don't add the full end-to-end checkout test because the checkout
// handler calls live Razorpay; mocking the razorpay-go client at this
// boundary requires more surface than this PR should touch. The contract
// is covered by:
//   - The validate-time tests above (do we recognise the code?).
//   - The webhook test above (does notes.admin_promo_code_id mark used_at?).
//
// Coverage gap: if a future refactor accidentally stops stamping the notes
// at checkout time, the validate-time + webhook tests both still pass; only
// the production wire would silently drop the redemption. The mitigation is
// the named constant checkoutNoteAdminPromoCodeID — both call sites read
// the same constant. A follow-up could add an integration test that swaps
// out the razorpay-go client; punted for now.

