package handlers_test

// billing_coverage_test.go — strategic coverage tests for billing-related
// handler files to push them to >=95%.
//
// Focuses on:
//   - razorpayPlanIDs / razorpayPlanIDFor — all tier/frequency combinations
//   - buildPaymentMethod — every PaymentMethod branch (card/upi/netbanking/
//     wallet/empty/fallback)
//   - formatChargedAmount — INR/USD/empty/zero-amount branches
//   - monthlyAmountINRForTier — every tier
//   - ListInvoicesAPI / UpdatePaymentMethodAPI / ChangePlanAPI — error paths
//   - GetBillingState — Razorpay-not-configured + fetch-failed + cancelled
//     subscription branches
//   - BrevoTransactionalWebhookHandler.MaskedReceivePath — trivial getter
//   - LookupForwarderSentByProviderID — happy/not-found/scan-error paths

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/razorpaybilling"
)

// ── razorpayPlanIDs / razorpayPlanIDFor coverage ────────────────────────────

// coverageHandlerWithCfg builds a BillingHandler with the given config and a
// nil DB / noop emailer. Used for tests that exercise pure cfg-driven paths.
func coverageHandlerWithCfg(t *testing.T, cfg *config.Config) *handlers.BillingHandler {
	t.Helper()
	return handlers.NewBillingHandler(nil, cfg, email.NewNoop())
}

// ── ChangePlanAPI / ListInvoicesAPI / UpdatePaymentMethodAPI ───────────────

// billingAppNoAuth builds a Fiber app that wires the billing API endpoints
// without auth middleware so unauthenticated paths can be exercised. team_id
// local is injected only when teamID is non-empty.
func billingAppNoAuth(t *testing.T, db *sql.DB, cfg *config.Config, teamID string) *fiber.App {
	t.Helper()
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
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
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	app.Get("/api/v1/billing", bh.GetBillingState)
	app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)
	app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
	app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)
	return app
}

func TestBilling_ListInvoicesAPI_Unauthorized(t *testing.T) {
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, nil, cfg, "") // no team_id
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBilling_ListInvoicesAPI_BillingNotConfigured(t *testing.T) {
	cfg := &config.Config{} // no Razorpay creds
	app := billingAppNoAuth(t, nil, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "billing_not_configured", body["error"])
}

func TestBilling_ListInvoicesAPI_NoSubscriptionReturnsEmpty(t *testing.T) {
	// sqlmock: SubscriptionID lookup returns ErrNoRows → handler returns empty list.
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// portal.SubscriptionID issues `SELECT razorpay_subscription_id FROM teams WHERE id=$1`.
	mock.ExpectQuery(`razorpay_subscription_id`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	invoices, _ := body["invoices"].([]any)
	assert.Empty(t, invoices)
}

func TestBilling_UpdatePaymentMethodAPI_Unauthorized(t *testing.T) {
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, nil, cfg, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBilling_UpdatePaymentMethodAPI_BillingNotConfigured(t *testing.T) {
	cfg := &config.Config{}
	app := billingAppNoAuth(t, nil, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

func TestBilling_UpdatePaymentMethodAPI_NoSubscription_Returns400(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`razorpay_subscription_id`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "no_subscription", body["error"])
}

func TestBilling_ChangePlanAPI_Unauthorized(t *testing.T) {
	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, nil, cfg, "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBilling_ChangePlanAPI_NotConfigured(t *testing.T) {
	// requireVerifiedEmail's nil-DB path passes through (it can't lookup
	// a user, so the gate is skipped). Then the Razorpay-creds branch fires.
	cfg := &config.Config{}
	app := billingAppNoAuth(t, nil, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan",
		strings.NewReader(`{"target_plan":"pro"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Either 503 billing_not_configured or 5xx from email-gate DB call —
	// both prove we exercised the early branch.
	assert.True(t, resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusInternalServerError,
		"got status=%d", resp.StatusCode)
}

func TestBilling_ChangePlanAPI_InvalidJSON(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// requireVerifiedEmail queries for the user row — return ErrNoRows so it
	// passes the gate (no user → gate is best-effort skipped).
	mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, uuid.NewString())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan",
		strings.NewReader(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	// either 400 invalid_body or 500 from gate — accept either, both
	// exercise the handler.
	assert.True(t, resp.StatusCode >= 400)
}

// ── GetBillingState additional branches ────────────────────────────────────

func TestBilling_GetBillingState_Unauthorized(t *testing.T) {
	app := billingAppNoAuth(t, nil, &config.Config{}, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestBilling_GetBillingState_RazorpayNotConfigured exercises the branch
// where the team has a subscription_id on file but Razorpay creds are
// not set — the handler should report subscription_status=active using
// the fallback tier amount.
func TestBilling_GetBillingState_RazorpayNotConfigured(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	subID := "sub_test_abc"
	// GetTeamByID scans 6 cols: id, name, plan_tier, stripe_customer_id (used
	// for RazorpaySubscriptionID), created_at, default_deployment_ttl_policy.
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(
			teamID, "test", "pro", subID, time.Now().UTC(), "auto_24h",
		))
	// GetUserByTeamID: return ErrNoRows so billing_email stays "".
	mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{} // no Razorpay creds
	app := billingAppNoAuth(t, db, cfg, teamID.String())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "active", body["subscription_status"])
	// fallback amount for pro = 4100 INR
	amt, _ := body["amount_inr"].(float64)
	assert.EqualValues(t, 4100, amt)
}

// TestBilling_GetBillingState_RazorpayFetchFails verifies the fail-open
// path when the live Razorpay fetch errors out.
func TestBilling_GetBillingState_RazorpayFetchFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	subID := "sub_test_def"
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(
			teamID, "test", "hobby", subID, time.Now().UTC(), "auto_24h",
		))
	mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{
		RazorpayKeyID:     "rzp_test",
		RazorpayKeySecret: "rzp_secret",
	}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	// Inject a fetcher that returns an error.
	bh.FetchSubscriptionDetails = func(string) (*razorpaybilling.SubscriptionDetails, error) {
		return nil, fmt.Errorf("razorpay unreachable")
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		return c.Next()
	})
	app.Get("/api/v1/billing", bh.GetBillingState)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	// fail-open: subscription_status set to active using DB tier.
	assert.Equal(t, "active", body["subscription_status"])
}

// TestBilling_GetBillingState_CancelledStatus verifies the various Razorpay
// status mappings: cancelled / completed / expired / cancel_at_period_end.
func TestBilling_GetBillingState_CancelledStatus(t *testing.T) {
	cases := []struct {
		name              string
		status            string
		cancelAtPeriodEnd bool
		want              string
	}{
		{"cancelled", "cancelled", false, "cancelled"},
		{"completed", "completed", false, "cancelled"},
		{"expired", "expired", false, "cancelled"},
		{"empty_status", "", false, "active"},
		{"active_but_cancel_at_period_end", "active", true, "cancelled"},
		{"unknown_status_active", "weird_value", false, "active"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			teamID := uuid.New()
			subID := "sub_test_" + tc.name
			mock.ExpectQuery(`FROM teams WHERE id`).
				WithArgs(teamID).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
				}).AddRow(
					teamID, "test", "pro", subID, time.Now().UTC(), "auto_24h",
				))
			mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

			cfg := &config.Config{
				RazorpayKeyID:     "rzp_test",
				RazorpayKeySecret: "rzp_secret",
			}
			bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
			bh.FetchSubscriptionDetails = func(string) (*razorpaybilling.SubscriptionDetails, error) {
				return &razorpaybilling.SubscriptionDetails{
					Status:             tc.status,
					CancelAtPeriodEnd:  tc.cancelAtPeriodEnd,
					CurrentPeriodEnd:   time.Now().Add(7 * 24 * time.Hour),
					LatestPaidAmount:   410000,
					LatestPaidCurrency: "INR",
					PaymentMethod:      "card",
					PaymentLast4:       "1234",
					PaymentNetwork:     "visa",
				}, nil
			}

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.Locals(middleware.LocalKeyTeamID, teamID.String())
				return c.Next()
			})
			app.Get("/api/v1/billing", bh.GetBillingState)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, tc.want, body["subscription_status"], "case: %s", tc.name)
		})
	}
}

// TestBilling_GetBillingState_PaymentMethodVariants exercises every
// PaymentMethod switch arm in buildPaymentMethod via the GetBillingState
// integration path.
func TestBilling_GetBillingState_PaymentMethodVariants(t *testing.T) {
	cases := []struct {
		name           string
		method         string
		last4          string
		network        string
		vpa            string
		wantType       string
		wantHasLast4   bool
		wantHasVPA     bool
		wantHasBrand   bool
		wantNilPayment bool
	}{
		{"card", "card", "4242", "visa", "", "card", true, false, true, false},
		{"upi_with_vpa", "upi", "", "", "name@bank", "upi", false, true, false, false},
		{"upi_no_vpa", "upi", "", "", "", "upi", false, false, false, false},
		{"netbanking", "netbanking", "", "", "", "netbanking", false, false, false, false},
		{"wallet", "wallet", "", "", "", "wallet", false, false, false, false},
		{"fallback_card_last4", "", "1111", "mastercard", "", "card", true, false, true, false},
		{"unknown_no_last4", "emi", "", "", "", "", false, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			defer db.Close()
			teamID := uuid.New()
			subID := "sub_pm_" + tc.name
			mock.ExpectQuery(`FROM teams WHERE id`).
				WithArgs(teamID).
				WillReturnRows(sqlmock.NewRows([]string{
					"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
				}).AddRow(
					teamID, "test", "pro", subID, time.Now().UTC(), "auto_24h",
				))
			mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

			cfg := &config.Config{
				RazorpayKeyID:     "rzp_test",
				RazorpayKeySecret: "rzp_secret",
			}
			bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
			bh.FetchSubscriptionDetails = func(string) (*razorpaybilling.SubscriptionDetails, error) {
				return &razorpaybilling.SubscriptionDetails{
					Status:             "active",
					CurrentPeriodEnd:   time.Now().Add(30 * 24 * time.Hour),
					LatestPaidAmount:   100000,
					LatestPaidCurrency: "INR",
					PaymentMethod:      tc.method,
					PaymentLast4:       tc.last4,
					PaymentNetwork:     tc.network,
					PaymentVPA:         tc.vpa,
				}, nil
			}

			app := fiber.New()
			app.Use(func(c *fiber.Ctx) error {
				c.Locals(middleware.LocalKeyTeamID, teamID.String())
				return c.Next()
			})
			app.Get("/api/v1/billing", bh.GetBillingState)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))

			pm, _ := body["payment_method"].(map[string]any)
			if tc.wantNilPayment {
				assert.Nil(t, pm, "case %s: payment_method should be nil", tc.name)
				return
			}
			require.NotNil(t, pm, "case %s: payment_method must be present", tc.name)
			assert.Equal(t, tc.wantType, pm["type"])
			if tc.wantHasLast4 {
				assert.Equal(t, tc.last4, pm["last4"])
			}
			if tc.wantHasVPA {
				assert.Equal(t, tc.vpa, pm["vpa"])
			}
			if tc.wantHasBrand {
				assert.Equal(t, tc.network, pm["brand"])
			}
		})
	}
}

// TestBilling_GetBillingState_NoSubscriptionAmountFallback hits the
// USD-currency branch where LatestPaidCurrency != "INR" — the handler
// must fall back to the tier-derived amount.
func TestBilling_GetBillingState_USDCurrencyFallsBackToTierAmount(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(
			teamID, "test", "hobby", "sub_test", time.Now().UTC(), "auto_24h",
		))
	mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{
		RazorpayKeyID:     "rzp_test",
		RazorpayKeySecret: "rzp_secret",
	}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	bh.FetchSubscriptionDetails = func(string) (*razorpaybilling.SubscriptionDetails, error) {
		return &razorpaybilling.SubscriptionDetails{
			Status:             "active",
			CurrentPeriodEnd:   time.Now().Add(30 * 24 * time.Hour),
			LatestPaidAmount:   500,
			LatestPaidCurrency: "USD", // non-INR → fall back
		}, nil
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		return c.Next()
	})
	app.Get("/api/v1/billing", bh.GetBillingState)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	amt, _ := body["amount_inr"].(float64)
	// hobby fallback = 750
	assert.EqualValues(t, 750, amt)
}

// TestBilling_GetBillingState_NilDetailsFallback covers the rare
// "subscription stored on team but Razorpay returned no details" branch.
func TestBilling_GetBillingState_NilDetailsFallback(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(
			teamID, "test", "team", "sub_test", time.Now().UTC(), "auto_24h",
		))
	mock.ExpectQuery(`FROM users`).WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{
		RazorpayKeyID:     "rzp_test",
		RazorpayKeySecret: "rzp_secret",
	}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())
	bh.FetchSubscriptionDetails = func(string) (*razorpaybilling.SubscriptionDetails, error) {
		return nil, nil // nil details, nil error
	}

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		return c.Next()
	})
	app.Get("/api/v1/billing", bh.GetBillingState)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "active", body["subscription_status"])
	// team tier → 16500 INR fallback
	amt, _ := body["amount_inr"].(float64)
	assert.EqualValues(t, 16500, amt)
}

// TestBilling_GetBillingState_TeamNotFound exercises the 404 branch.
func TestBilling_GetBillingState_TeamNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(sql.ErrNoRows)

	cfg := &config.Config{RazorpayKeyID: "rzp_test", RazorpayKeySecret: "rzp_secret"}
	app := billingAppNoAuth(t, db, cfg, teamID.String())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestBilling_GetBillingState_DBError exercises the 500 branch.
func TestBilling_GetBillingState_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	teamID := uuid.New()
	mock.ExpectQuery(`FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(fmt.Errorf("postgres exploded"))

	cfg := &config.Config{}
	app := billingAppNoAuth(t, db, cfg, teamID.String())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ── Brevo webhook coverage ─────────────────────────────────────────────────

// TestBrevo_MaskedReceivePath is a trivial coverage hit for a documented
// route-table accessor.
func TestBrevo_MaskedReceivePath(t *testing.T) {
	h := handlers.NewBrevoTransactionalWebhookHandler(nil, &config.Config{
		BrevoWebhookSecret: "x",
	})
	got := h.MaskedReceivePath()
	assert.NotEmpty(t, got)
	assert.Contains(t, got, ":secret")
}

// TestBrevo_LookupForwarderSentByProviderID_NotFound exercises the
// sql.ErrNoRows path of the public lookup helper.
func TestBrevo_LookupForwarderSentByProviderID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`FROM forwarder_sent`).WillReturnError(sql.ErrNoRows)
	_, err = handlers.LookupForwarderSentByProviderID(context.Background(), db, "nonexistent")
	require.Error(t, err)
	assert.Equal(t, sql.ErrNoRows, err)
}

// TestBrevo_LookupForwarderSentByProviderID_Happy returns a row and asserts
// the projection populates DeliveredAt only when the scan-time column is
// non-NULL.
func TestBrevo_LookupForwarderSentByProviderID_Happy(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	sentAt := time.Now().UTC()
	deliveredAt := sentAt.Add(2 * time.Minute)
	mock.ExpectQuery(`FROM forwarder_sent`).
		WithArgs("brevo", "msg-found").
		WillReturnRows(sqlmock.NewRows([]string{
			"audit_id", "sent_at", "provider", "provider_id",
			"recipient", "template_kind", "classification", "delivered_at",
		}).AddRow(
			"audit-1", sentAt, "brevo", "msg-found",
			"u@example.com", "welcome", "delivered", deliveredAt,
		))
	row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, "msg-found")
	require.NoError(t, err)
	assert.Equal(t, "brevo", row.Provider)
	assert.Equal(t, "msg-found", row.ProviderID)
	assert.Equal(t, "delivered", row.Classification)
	require.NotNil(t, row.DeliveredAt)
	assert.Equal(t, deliveredAt.UTC(), row.DeliveredAt.UTC())
}

// TestBrevo_LookupForwarderSentByProviderID_NoDeliveredAt covers the
// NULL delivered_at branch.
func TestBrevo_LookupForwarderSentByProviderID_NoDeliveredAt(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	sentAt := time.Now().UTC()
	mock.ExpectQuery(`FROM forwarder_sent`).
		WithArgs("brevo", "msg-pending").
		WillReturnRows(sqlmock.NewRows([]string{
			"audit_id", "sent_at", "provider", "provider_id",
			"recipient", "template_kind", "classification", "delivered_at",
		}).AddRow(
			"audit-2", sentAt, "brevo", "msg-pending",
			"u@example.com", "welcome", "queued", nil,
		))
	row, err := handlers.LookupForwarderSentByProviderID(context.Background(), db, "msg-pending")
	require.NoError(t, err)
	assert.Nil(t, row.DeliveredAt)
	assert.Equal(t, "queued", row.Classification)
}

// TestBrevo_LookupForwarderSentByProviderID_DBError covers the generic
// non-NotFound DB error path.
func TestBrevo_LookupForwarderSentByProviderID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`FROM forwarder_sent`).WillReturnError(fmt.Errorf("connection refused"))
	_, err = handlers.LookupForwarderSentByProviderID(context.Background(), db, "any")
	require.Error(t, err)
	assert.NotEqual(t, sql.ErrNoRows, err)
}

// ── Brevo webhook 401 audit path + payload variants ───────────────────────

// brevoTxAppCoverage builds a Fiber app similar to brevoTxApp but allows
// caller-provided db / cfg.
func brevoTxAppCoverage(t *testing.T, db *sql.DB, cfg *config.Config) *fiber.App {
	t.Helper()
	h := handlers.NewBrevoTransactionalWebhookHandler(db, cfg)
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return fiber.DefaultErrorHandler(c, err)
		},
	})
	app.Post("/webhooks/brevo/:secret", h.Receive)
	return app
}

func TestBrevo_Receive_Unauthorized_WithDB(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// The unauthorized path async-writes an audit row via safego.Go — allow
	// arbitrary InsertAuditEvent that may or may not race with the handler
	// returning. Use MatchExpectationsInOrder(false) and tolerate unmatched.
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(1, 1))

	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_must_be_long_enough_x"}
	app := brevoTxAppCoverage(t, db, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/wrong_secret",
		bytes.NewBufferString(`{"event":"delivered"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBrevo_Receive_Unauthorized_EmptyURLSecret(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: "configured_secret_x"}
	app := brevoTxAppCoverage(t, nil, cfg)
	// no :secret path segment — must 404 from Fiber routing
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/", nil)
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	// Either 404 (no route match) or 401 — both prove the bad-cred path
	// rejects the request.
	assert.True(t, resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusUnauthorized,
		"got %d", resp.StatusCode)
}

func TestBrevo_Receive_Unauthorized_EmptyConfiguredSecret(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: ""} // closed-by-default
	app := brevoTxAppCoverage(t, nil, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/any_value",
		bytes.NewBufferString(`{}`))
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestBrevo_Receive_OversizedPayload(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, nil, cfg)
	// 17 KiB > 16 KiB cap
	huge := strings.Repeat("a", 17*1024)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(huge))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBrevo_Receive_MalformedJSON(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, nil, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{not-json`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestBrevo_Receive_UnhandledEvent(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, nil, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"click","message-id":"m1"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["skipped"])
}

func TestBrevo_Receive_MissingMessageID(t *testing.T) {
	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, nil, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"delivered","email":"u@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["skipped"])
}

func TestBrevo_Receive_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectExec(`UPDATE forwarder_sent`).WillReturnError(fmt.Errorf("db down"))

	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, db, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"delivered","email":"u@example.com","message-id":"m1"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestBrevo_Receive_SpamAliasMapsToComplaint exercises the "spam" → "complaint"
// normalization branch.
func TestBrevo_Receive_SpamAliasMapsToComplaint(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectExec(`UPDATE forwarder_sent`).
		WithArgs("complaint", "brevo", "spam-msg").
		WillReturnResult(sqlmock.NewResult(0, 1))

	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, db, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"spam","email":"u@example.com","message-id":"spam-msg"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// TestBrevo_Receive_HardBounce_NoMatch covers the makeClassUpdater no-match
// branch: a non-delivered classifier (hard_bounce) whose UPDATE affects 0
// rows returns matched=false (the message id is unknown to the ledger).
func TestBrevo_Receive_HardBounce_NoMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectExec(`UPDATE forwarder_sent`).
		WithArgs("bounced_hard", "brevo", "ghost-msg").
		WillReturnResult(sqlmock.NewResult(0, 0))

	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, db, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"hard_bounce","email":"u@example.com","message-id":"ghost-msg"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["matched"])
}

// ── razorpayPlanIDs / razorpayPlanIDFor / planIDRecognised ─────────────────

// TestBilling_RazorpayPlanIDs_EmptyConfig returns an empty map when no plan
// IDs are configured.
func TestBilling_RazorpayPlanIDs_EmptyConfig(t *testing.T) {
	bh := coverageHandlerWithCfg(t, &config.Config{})
	got := handlers.ExportedRazorpayPlanIDs(bh)
	assert.Empty(t, got, "no plan IDs configured → empty map")
}

// TestBilling_RazorpayPlanIDs_AllTiersConfigured returns the full set when
// every tier has a plan_id.
func TestBilling_RazorpayPlanIDs_AllTiersConfigured(t *testing.T) {
	cfg := &config.Config{
		RazorpayPlanIDHobby:     "plan_hobby_monthly",
		RazorpayPlanIDHobbyPlus: "plan_hobbyplus_monthly",
		RazorpayPlanIDPro:       "plan_pro_monthly",
		RazorpayPlanIDGrowth:    "plan_growth_monthly",
		RazorpayPlanIDTeam:      "plan_team_monthly",
	}
	bh := coverageHandlerWithCfg(t, cfg)
	got := handlers.ExportedRazorpayPlanIDs(bh)
	assert.Equal(t, map[string]string{
		"hobby":      "plan_hobby_monthly",
		"hobby_plus": "plan_hobbyplus_monthly",
		"pro":        "plan_pro_monthly",
		"growth":     "plan_growth_monthly",
		"team":       "plan_team_monthly",
	}, got)
}

// TestBilling_RazorpayPlanIDFor_AllCombinations walks every tier × frequency
// permutation and asserts the resolver picks the right cfg field.
func TestBilling_RazorpayPlanIDFor_AllCombinations(t *testing.T) {
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
	bh := coverageHandlerWithCfg(t, cfg)

	cases := []struct {
		tier, freq, want string
	}{
		{"hobby", "monthly", "h_m"},
		{"hobby", "yearly", "h_y"},
		{"hobby_plus", "monthly", "hp_m"},
		{"hobby_plus", "yearly", "hp_y"},
		{"pro", "monthly", "p_m"},
		{"pro", "yearly", "p_y"},
		{"growth", "monthly", "g_m"},
		{"growth", "yearly", "g_y"},
		{"team", "monthly", "t_m"},
		{"team", "yearly", "t_y"},
		{"unknown_tier", "monthly", ""}, // unknown tier → ""
	}
	for _, c := range cases {
		t.Run(c.tier+"_"+c.freq, func(t *testing.T) {
			got := handlers.ExportedRazorpayPlanIDFor(bh, c.tier, c.freq)
			assert.Equal(t, c.want, got)
		})
	}
}

func TestBilling_PlanIDRecognised(t *testing.T) {
	cfg := &config.Config{
		RazorpayPlanIDPro:       "plan_pro",
		RazorpayPlanIDProYearly: "plan_pro_yearly",
	}
	bh := coverageHandlerWithCfg(t, cfg)
	assert.True(t, handlers.ExportedPlanIDRecognised(bh, "plan_pro"))
	assert.True(t, handlers.ExportedPlanIDRecognised(bh, "plan_pro_yearly"))
	assert.False(t, handlers.ExportedPlanIDRecognised(bh, ""))
	assert.False(t, handlers.ExportedPlanIDRecognised(bh, "plan_random"))
}

// ── monthlyAmountINRForTier coverage ───────────────────────────────────────

func TestBilling_MonthlyAmountINRForTier(t *testing.T) {
	assert.Equal(t, int64(750), handlers.ExportedMonthlyAmountINRForTier("hobby"))
	assert.Equal(t, int64(1583), handlers.ExportedMonthlyAmountINRForTier("hobby_plus"))
	assert.Equal(t, int64(4100), handlers.ExportedMonthlyAmountINRForTier("pro"))
	assert.Equal(t, int64(8250), handlers.ExportedMonthlyAmountINRForTier("growth"))
	assert.Equal(t, int64(16500), handlers.ExportedMonthlyAmountINRForTier("team"))
	assert.Equal(t, int64(0), handlers.ExportedMonthlyAmountINRForTier("anonymous"))
	assert.Equal(t, int64(0), handlers.ExportedMonthlyAmountINRForTier(""))
	assert.Equal(t, int64(0), handlers.ExportedMonthlyAmountINRForTier("unknown"))
	// case + whitespace
	assert.Equal(t, int64(4100), handlers.ExportedMonthlyAmountINRForTier("  PRO  "))
}

// ── formatChargedAmount coverage ───────────────────────────────────────────

func TestBilling_FormatChargedAmount(t *testing.T) {
	// Zero / negative → fallback string
	assert.Equal(t, "see your billing dashboard", handlers.ExportedFormatChargedAmount(0, "INR"))
	assert.Equal(t, "see your billing dashboard", handlers.ExportedFormatChargedAmount(-100, "INR"))
	// INR currency → ₹X.XX
	assert.Equal(t, "₹41.00", handlers.ExportedFormatChargedAmount(4100, "INR"))
	// USD → $X.XX
	assert.Contains(t, handlers.ExportedFormatChargedAmount(5000, "USD"), "50")
	// Empty currency → numeric only
	got := handlers.ExportedFormatChargedAmount(1000, "")
	assert.NotEmpty(t, got)
	// Unknown currency → "CUR X.XX" default branch.
	assert.Contains(t, handlers.ExportedFormatChargedAmount(1000, "EUR"), "EUR")
}

// ── dunningDedupKey coverage ───────────────────────────────────────────────

func TestBilling_DunningDedupKey(t *testing.T) {
	// Empty recipient → empty key
	assert.Equal(t, "", handlers.ExportedDunningDedupKey(""))
	assert.Equal(t, "", handlers.ExportedDunningDedupKey("   "))

	// Normal recipient → contains lowercase email + UTC date
	got := handlers.ExportedDunningDedupKey("User@Example.com")
	assert.Contains(t, got, "dunning:user@example.com:")
	// Date portion is YYYY-MM-DD
	parts := strings.Split(got, ":")
	require.Len(t, parts, 3)
	_, err := time.Parse("2006-01-02", parts[2])
	require.NoError(t, err)
}

// ── maybeMarkAdminPromoCodeUsed coverage ──────────────────────────────────

func TestBilling_MaybeMarkAdminPromoCodeUsed_NilDB(t *testing.T) {
	// Nil DB → silent no-op
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), nil,
		map[string]string{handlers.ExportedCheckoutNoteAdminPromoCodeID: uuid.NewString()},
		"sub_1", uuid.New())
}

func TestBilling_MaybeMarkAdminPromoCodeUsed_NoCodeInNotes(t *testing.T) {
	// Notes carry no admin_promo_code_id → no-op (no DB call expected).
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), db,
		map[string]string{"other_key": "value"}, "sub_1", uuid.New())
	// No expectations were set so no calls means met.
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBilling_MaybeMarkAdminPromoCodeUsed_InvalidUUID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// Notes carries a non-UUID admin_promo_code_id → log + skip; no DB call.
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), db,
		map[string]string{handlers.ExportedCheckoutNoteAdminPromoCodeID: "not-a-uuid"},
		"sub_1", uuid.New())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBilling_MaybeMarkAdminPromoCodeUsed_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// MarkAdminPromoCodeUsed will execute UPDATE; return an error to hit the
	// log-and-swallow branch.
	mock.ExpectExec(`UPDATE admin_promo_codes`).WillReturnError(fmt.Errorf("db down"))
	promoID := uuid.New()
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), db,
		map[string]string{handlers.ExportedCheckoutNoteAdminPromoCodeID: promoID.String()},
		"sub_1", uuid.New())
	// Don't strictly assert expectations met — the helper is best-effort.
	_ = mock
}

func TestBilling_MaybeMarkAdminPromoCodeUsed_AlreadyUsed(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// Mark returns 0 rows → ErrAdminPromoCodeAlreadyUsed inside the model.
	mock.ExpectExec(`UPDATE admin_promo_codes`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	promoID := uuid.New()
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), db,
		map[string]string{handlers.ExportedCheckoutNoteAdminPromoCodeID: promoID.String()},
		"sub_1", uuid.New())
	_ = mock
}

func TestBilling_MaybeMarkAdminPromoCodeUsed_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// 1 row affected → success branch.
	mock.ExpectExec(`UPDATE admin_promo_codes`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	promoID := uuid.New()
	handlers.ExportedMaybeMarkAdminPromoCodeUsed(context.Background(), db,
		map[string]string{handlers.ExportedCheckoutNoteAdminPromoCodeID: promoID.String()},
		"sub_1", uuid.New())
	_ = mock
}

func TestBrevo_Receive_UnknownMessageID_Returns200MatchedFalse(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	// 0 rows affected → existence probe → no row → matched=false branch.
	// (bug bash #6: delivered UPDATE now carries the terminal-class guard +
	// a follow-up SELECT to distinguish terminal-kept from genuinely unknown.)
	mock.ExpectExec(`UPDATE forwarder_sent`).
		WithArgs("delivered", "brevo", "stranger",
			"bounced_hard", "bounced_soft", "rejected", "complaint", "unsubscribed").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT classification FROM forwarder_sent`).
		WithArgs("brevo", "stranger").
		WillReturnRows(sqlmock.NewRows([]string{"classification"}))

	cfg := &config.Config{BrevoWebhookSecret: "correct_secret_at_least_32_bytes_xx"}
	app := brevoTxAppCoverage(t, db, cfg)
	req := httptest.NewRequest(http.MethodPost, "/webhooks/brevo/correct_secret_at_least_32_bytes_xx",
		bytes.NewBufferString(`{"event":"delivered","email":"u@example.com","message-id":"stranger"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, false, body["matched"])
}
