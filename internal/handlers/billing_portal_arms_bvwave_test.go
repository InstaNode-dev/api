package handlers_test

// billing_portal_arms_bvwave_test.go — covers the POST-subscription network
// arms of ListInvoicesAPI / UpdatePaymentMethodAPI / ChangePlanAPI in
// billing.go. The existing billing_coverage_test.go covers the early arms
// (unauthorized / billing_not_configured / no_subscription / invalid-json),
// but the success + circuit-open + razorpay-error arms after a subscription is
// resolved require a Razorpay client — previously unreachable under CI.
//
// We inject a FAKE handlers.BillingPortal via handlers.SetBillingPortalForTest
// (NEVER a real network call, NEVER the rzp_live key). The fake returns canned
// invoices / payment-update URLs / change-plan results for the happy arms, and
// circuit.ErrOpen or a plain error for the failure arms. ChangePlanAPI also
// reads teams.plan_tier directly via the handler DB, so those subtests use a
// real test DB with a seeded team row.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/circuit"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/razorpaybilling"
	"instant.dev/internal/testhelpers"
)

// bvFakePortal is a programmable handlers.BillingPortal. Every method returns
// the canned value/error set on the struct so each endpoint arm is reachable
// without a live Razorpay account.
type bvFakePortal struct {
	subID      string
	subErr     error
	invoices   []razorpaybilling.Invoice
	invoiceErr error
	payURL     string
	payErr     error
	changeRes  *razorpaybilling.ChangePlanResult
	changeErr  error
}

func (p *bvFakePortal) SubscriptionID(ctx context.Context, teamID uuid.UUID) (string, error) {
	return p.subID, p.subErr
}
func (p *bvFakePortal) ListSubscriptionInvoices(subID string) ([]razorpaybilling.Invoice, error) {
	return p.invoices, p.invoiceErr
}
func (p *bvFakePortal) PaymentUpdateURL(subID string) (string, error) {
	return p.payURL, p.payErr
}
func (p *bvFakePortal) ChangePlan(ctx context.Context, teamID uuid.UUID, target string, planIDs map[string]string) (*razorpaybilling.ChangePlanResult, error) {
	return p.changeRes, p.changeErr
}

// bvBillingApp builds a Fiber app that injects team_id into the ctx (no auth
// middleware) so the portal-backed endpoints can be exercised directly.
func bvBillingApp(t *testing.T, teamID string) *fiber.App {
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
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	return app
}

func bvCfgRzp() *config.Config {
	return &config.Config{
		RazorpayKeyID:       "rzp_test",
		RazorpayKeySecret:   "rzp_secret",
		RazorpayPlanIDHobby: "plan_hobby",
		RazorpayPlanIDPro:   "plan_pro",
	}
}

func TestBilling_ListInvoicesAPI_PortalArms_bvwave(t *testing.T) {
	teamID := uuid.NewString()

	t.Run("success_with_invoices", func(t *testing.T) {
		fake := &bvFakePortal{
			subID: "sub_123",
			invoices: []razorpaybilling.Invoice{
				{ID: "inv_1", Amount: 9900, Currency: "INR", Status: "paid", Date: time.Now(), PDFURL: "https://pdf"},
			},
		}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()

		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)

		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body struct {
			OK       bool             `json:"ok"`
			Invoices []map[string]any `json:"invoices"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.True(t, body.OK)
		require.Len(t, body.Invoices, 1)
		assert.Equal(t, "inv_1", body.Invoices[0]["id"])
	})

	t.Run("circuit_open_503", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", invoiceErr: circuit.ErrOpen}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()
		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("razorpay_error_502", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", invoiceErr: errors.New("boom")}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()
		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Get("/api/v1/billing/invoices", bh.ListInvoicesAPI)
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/billing/invoices", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})
}

func TestBilling_UpdatePaymentMethodAPI_PortalArms_bvwave(t *testing.T) {
	teamID := uuid.NewString()

	t.Run("success", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", payURL: "https://razorpay/update"}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()
		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "https://razorpay/update", body["short_url"])
	})

	t.Run("circuit_open_503", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", payErr: circuit.ErrOpen}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()
		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("no_update_url_422", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", payErr: errors.New("no payment update URL available")}
		rst := handlers.SetBillingPortalForTestPortal(fake)
		defer rst()
		bh := handlers.NewBillingHandler(nil, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Post("/api/v1/billing/update-payment", bh.UpdatePaymentMethodAPI)
		resp, err := app.Test(httptest.NewRequest(http.MethodPost, "/api/v1/billing/update-payment", nil), 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	})
}

func TestBilling_ChangePlanAPI_PortalArms_bvwave(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	// Seed a hobby team so the SELECT plan_tier returns a row and a pro upgrade
	// is a genuine rank-increase (not a downgrade).
	teamID := testhelpers.MustCreateTeamDB(t, db, "hobby")

	postChange := func(t *testing.T, fake *bvFakePortal, target string) *http.Response {
		t.Helper()
		rst := handlers.SetBillingPortalForTestPortal(fake)
		t.Cleanup(rst)
		bh := handlers.NewBillingHandler(db, bvCfgRzp(), email.NewNoop())
		app := bvBillingApp(t, teamID)
		app.Post("/api/v1/billing/change-plan", bh.ChangePlanAPI)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/change-plan",
			strings.NewReader(`{"target_plan":"`+target+`"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		return resp
	}

	t.Run("success", func(t *testing.T) {
		fake := &bvFakePortal{
			subID: "sub_123",
			changeRes: &razorpaybilling.ChangePlanResult{
				NewPlan: "pro", EffectiveDate: time.Now(), CheckoutShort: "https://rzp/co",
			},
		}
		resp := postChange(t, fake, "pro")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "pro", body["new_plan"])
	})

	t.Run("circuit_open_503", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", changeErr: circuit.ErrOpen}
		resp := postChange(t, fake, "pro")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("razorpay_error_502", func(t *testing.T) {
		fake := &bvFakePortal{subID: "sub_123", changeErr: errors.New("rzp boom")}
		resp := postChange(t, fake, "pro")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("no_subscription_400", func(t *testing.T) {
		// SubscriptionID errors → handler returns no_subscription 400.
		fake := &bvFakePortal{subErr: errors.New("no subscription on file")}
		resp := postChange(t, fake, "pro")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}
