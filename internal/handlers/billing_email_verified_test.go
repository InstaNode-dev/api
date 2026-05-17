package handlers_test

// billing_email_verified_test.go — coverage for the email-verified billing
// gate (migration 052 / DECISION 2026-05-17).
//
// A /claim-created account reaches the dashboard with email_verified=false
// because the claim does not prove inbox ownership. The billing checkout +
// change-plan handlers must refuse such a user with 403 email_not_verified
// until they verify (via a magic-link sign-in). A user with email_verified
// =true must clear the gate.
//
// These tests require a real DB (the gate reads the user row via
// models.GetUserByID) — they skip when TEST_DATABASE_URL is unset.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
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

// billingGateNeedsDB skips when no TEST_DATABASE_URL is configured.
func billingGateNeedsDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("billing email-verified gate: TEST_DATABASE_URL not set — skipping integration test")
	}
}

// checkoutGateApp builds a Fiber app exposing CreateCheckoutAPI with team +
// user locals pre-stamped (RequireAuth would set these in production).
func checkoutGateApp(t *testing.T, bh *handlers.BillingHandler, teamID, userID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			// Mirror the production + testhelpers ErrorHandler: respond*
			// helpers write the response and return the ErrResponseWritten
			// sentinel — it MUST NOT be turned into a 500, the real status
			// (e.g. the gate's 403) was already written.
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).
				JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		c.Locals(middleware.LocalKeyUserID, userID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)
	return app
}

// TestCheckout_UnverifiedEmail_Returns403 is the core regression: a user with
// email_verified=false (the /claim default) is refused checkout with 403
// email_not_verified + an agent_action telling them to verify.
func TestCheckout_UnverifiedEmail_Returns403(t *testing.T) {
	billingGateNeedsDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	teamUUID := uuid.MustParse(teamID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamUUID)

	// A /claim-created user: CreateUser inserts email_verified=false.
	user, err := models.CreateUser(ctx, db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	require.False(t, user.EmailVerified, "precondition: /claim user starts unverified")
	defer db.Exec(`DELETE FROM users WHERE id = $1`, user.ID)

	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		RazorpayKeyID:     "rzp_test_key",
		RazorpayKeySecret: "rzp_test_secret",
		RazorpayPlanIDPro: "plan_monthly_pro",
	}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := checkoutGateApp(t, bh, teamID, user.ID.String())

	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an unverified user must be blocked from checkout with 403")

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "email_not_verified", body["error"],
		"the error code must be the named email_not_verified")
	assert.NotEmpty(t, body["agent_action"],
		"the 403 must carry an agent_action guiding the user to verify")
}

// TestCheckout_VerifiedEmail_ClearsGate verifies the gate does NOT block a
// user whose email_verified is true. The handler proceeds past the gate (it
// later returns a non-403 — here a 503 billing_not_configured stand-in is
// fine; the assertion is simply "not 403 email_not_verified").
func TestCheckout_VerifiedEmail_ClearsGate(t *testing.T) {
	billingGateNeedsDB(t)
	db, cleanup := testhelpers.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	teamUUID := uuid.MustParse(teamID)
	defer db.Exec(`DELETE FROM teams WHERE id = $1`, teamUUID)

	user, err := models.CreateUser(ctx, db, teamUUID, testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	defer db.Exec(`DELETE FROM users WHERE id = $1`, user.ID)
	// Verify the email — simulates a completed magic-link / OAuth login.
	require.NoError(t, models.SetEmailVerified(ctx, db, user.ID))

	// Razorpay deliberately left unconfigured: the handler will 503
	// billing_not_configured AFTER passing the gate. The assertion is the
	// gate did NOT fire — the response is not 403 email_not_verified.
	cfg := &config.Config{JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!"}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	app := checkoutGateApp(t, bh, teamID, user.ID.String())

	b, _ := json.Marshal(map[string]any{"plan": "pro"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.NotEqual(t, http.StatusForbidden, resp.StatusCode,
		"a verified user must clear the email-verified gate")
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEqual(t, "email_not_verified", body["error"],
		"a verified user must not see the email_not_verified error")
}
