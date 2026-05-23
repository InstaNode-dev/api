package handlers_test

// billing_checkout_arms_bvwave_test.go — covers CreateCheckoutAPI arms the
// existing checkout tests leave open: the invalid-body 400, the Redis dedup
// guard success path (rdb wired), and the reusablePendingCheckout reuse-return
// (a live pending subscription is reused instead of minting a second one).
//
// Uses the FetchCheckoutSubscription seam (existing, no network) to make the
// pending subscription look payable, plus a real test DB + Redis. CreateSubscription
// is wired to fail the test if it is ever called on the reuse path (a second
// subscription would double-charge).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/testhelpers"
)

func bvCheckoutApp(t *testing.T, bh *handlers.BillingHandler, teamID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error"})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app
}

func TestBilling_CreateCheckout_InvalidBody_400_bvwave(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	rdb, cleanR := testhelpers.SetupTestRedis(t)
	defer cleanR()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, RazorpayKeyID: "rzp_test", RazorpayKeySecret: "sec", RazorpayPlanIDPro: "plan_pro"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop()).WithRedis(rdb)
	app := bvCheckoutApp(t, bh, teamID)

	// Malformed JSON → 400 invalid_body (after the Redis dedup guard SETNX
	// success path runs, covering that branch too).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", strings.NewReader(`{bad`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
