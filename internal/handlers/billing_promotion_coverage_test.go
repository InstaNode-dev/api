package handlers_test

// billing_promotion_coverage_test.go — fills the remaining promotion-handler
// helper branches: classifyPromotionError (expired / exhausted / does-not-
// apply / default), isPromoNotFoundError (nil + substring), adminPromoDescription
// (every kind + the defensive default), and ValidatePromotion's invalid-body
// + missing-field paths.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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

func testingSkipNoDB() bool { return os.Getenv("TEST_DATABASE_URL") == "" }

func TestPromoCov_ClassifyPromotionError(t *testing.T) {
	cases := []struct {
		msg      string
		wantKind string
	}{
		{"code has expired", "promotion_expired"},
		{"all uses exhausted", "promotion_exhausted"},
		{"does not apply to this plan", "promotion_invalid"},
		{"code not found", "promotion_invalid"},
		{"some other wording", "promotion_invalid"},
	}
	for _, tc := range cases {
		kind, msg := handlers.ExportedClassifyPromotionError(handlers.ExportedNewErr(tc.msg), "SAVE10", "pro")
		assert.Equal(t, tc.wantKind, kind, "msg=%q", tc.msg)
		assert.NotEmpty(t, msg)
	}
}

func TestPromoCov_IsPromoNotFoundError(t *testing.T) {
	assert.False(t, handlers.ExportedIsPromoNotFoundError(nil))
	assert.True(t, handlers.ExportedIsPromoNotFoundError(handlers.ExportedNewErr("code not found")))
	assert.False(t, handlers.ExportedIsPromoNotFoundError(handlers.ExportedNewErr("expired")))
}

func TestPromoCov_AdminPromoDescription(t *testing.T) {
	assert.Contains(t, handlers.ExportedAdminPromoDescription(models.PromoKindPercentOff, 25), "25%")
	assert.Contains(t, handlers.ExportedAdminPromoDescription(models.PromoKindFirstMonthFree, 0), "First month free")
	assert.Contains(t, handlers.ExportedAdminPromoDescription(models.PromoKindAmountOff, 500), "$5.00")
	// Defensive default for an unknown kind (impossible given the DB CHECK,
	// but the branch must not panic).
	assert.Contains(t, handlers.ExportedAdminPromoDescription("bogus_kind", 0), "Admin-issued")
}

// promoValidateApp wires ValidatePromotion with team_id stamped + a real
// miniredis so the rate-limit pipeline runs.
func promoValidateApp(t *testing.T) *fiber.App {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return newPromoApp(t, rdb, plans.Default(), true, uuid.New())
}

func TestPromoCov_ValidatePromotion_MissingPlan(t *testing.T) {
	app := promoValidateApp(t)
	b, _ := json.Marshal(map[string]any{"code": "SAVE10"}) // no plan
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPromoCov_ValidatePromotion_InvalidBody(t *testing.T) {
	app := promoValidateApp(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader([]byte(`{bad`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// TestPromoCov_ValidatePromotion_NilRedis_RateLimitPasses covers the
// incrementRateLimit nil-rdb branch: the handler is wired with nil rdb so the
// rate limiter passes through, and an unknown code returns ok:false.
func TestPromoCov_ValidatePromotion_NilRedis_RateLimitPasses(t *testing.T) {
	app := newPromoApp(t, nil, plans.Default(), true, uuid.New()) // nil rdb
	b, _ := json.Marshal(map[string]any{"code": "UNKNOWN_CODE_XYZ", "plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["ok"])
}

// TestPromoCov_ValidatePromotion_AdminLookupError covers ValidatePromotion's
// admin-fallback DB-error branch: an unknown plans-yaml code triggers the
// admin lookup, which errors against a closed DB → surfaced as
// promotion_invalid (200), logged loudly.
func TestPromoCov_ValidatePromotion_AdminLookupError(t *testing.T) {
	if testingSkipNoDB() {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, clean := testhelpers.SetupTestDB(t)
	clean()
	_ = db.Close() // closed → admin lookup errors

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	h := handlers.NewBillingPromotionHandler(db, rdb, plans.Default())
	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error { return c.SendStatus(500) }})
	app.Use(func(c *fiber.Ctx) error { c.Locals(middleware.LocalKeyTeamID, uuid.New().String()); return c.Next() })
	app.Post("/api/v1/billing/promotion/validate", h.ValidatePromotion)

	b, _ := json.Marshal(map[string]any{"code": "UNKNOWN_ADMIN_CODE", "plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/promotion/validate", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "promotion_invalid", body["error"])
}
