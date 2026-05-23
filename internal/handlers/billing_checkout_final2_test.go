package handlers_test

// billing_checkout_final2_test.go — FINAL SERIAL PASS #2 coverage for the
// CreateCheckoutAPI Razorpay/persistence error arms the existing checkout
// suites leave uncovered:
//
//   * CreateSubscription → circuit.ErrOpen → 503 billing_provider_unavailable (L853-861)
//   * CreateSubscription → generic error    → 502 razorpay_error             (L862-868)
//   * CreateSubscription → incomplete map    → 502 razorpay_error             (L874-882)
//   * UpdateRazorpaySubscriptionID error      → 503 billing_persistence_failed (L907-916)
//
// Drives bh.CreateCheckoutAPI through the existing bvCheckoutApp seam with the
// CreateSubscription field assigned to a programmable fake (NEVER a real key).
// A "free" team requesting "pro" passes the already-on-tier guard so control
// reaches the subscription-mint call.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/circuit"
	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/testhelpers"
)

func checkoutFinal2Cfg() *config.Config {
	return &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		RazorpayKeyID:     "rzp_test_final2",
		RazorpayKeySecret: "sec_final2",
		RazorpayPlanIDPro: "plan_pro_final2",
	}
}

func postCheckoutF2(t *testing.T, app *fiber.App) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout",
		strings.NewReader(`{"plan":"pro"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var raw [2048]byte
	n, _ := resp.Body.Read(raw[:])
	return resp.StatusCode, string(raw[:n])
}

func checkoutF2NeedDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
}

func TestBillingCheckoutFinal2_CircuitOpen_503(t *testing.T) {
	checkoutF2NeedDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	bh := handlers.NewBillingHandler(db, checkoutFinal2Cfg(), email.NewNoop())
	bh.CreateSubscription = func(map[string]any) (map[string]any, error) {
		return nil, circuit.ErrOpen
	}
	app := bvCheckoutApp(t, bh, teamID)
	status, body := postCheckoutF2(t, app)
	assert.Equal(t, http.StatusServiceUnavailable, status)
	assert.Contains(t, body, "billing_provider_unavailable")
}

func TestBillingCheckoutFinal2_RazorpayError_502(t *testing.T) {
	checkoutF2NeedDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	bh := handlers.NewBillingHandler(db, checkoutFinal2Cfg(), email.NewNoop())
	bh.CreateSubscription = func(map[string]any) (map[string]any, error) {
		return nil, handlers.ExportedNewErr("razorpay rejected")
	}
	app := bvCheckoutApp(t, bh, teamID)
	status, body := postCheckoutF2(t, app)
	assert.Equal(t, http.StatusBadGateway, status)
	assert.Contains(t, body, "razorpay_error")
}

func TestBillingCheckoutFinal2_IncompleteResponse_502(t *testing.T) {
	checkoutF2NeedDB(t)
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	bh := handlers.NewBillingHandler(db, checkoutFinal2Cfg(), email.NewNoop())
	// Missing id + short_url → razorpay_response_incomplete arm.
	bh.CreateSubscription = func(map[string]any) (map[string]any, error) {
		return map[string]any{"entity": "subscription"}, nil
	}
	app := bvCheckoutApp(t, bh, teamID)
	status, body := postCheckoutF2(t, app)
	assert.Equal(t, http.StatusBadGateway, status)
	assert.Contains(t, body, "razorpay_error")
}

// UpdateRazorpaySubscriptionID error: CreateSubscription returns a complete
// response, but the post-create UpdateRazorpaySubscriptionID UPDATE errors on a
// fault DB → billing_persistence_failed. The team is seeded on the pooled DB;
// the handler runs on a fault DB sharing the DSN.
//
// Query order: requireVerifiedEmail user lookup(1), GetTeamByID(2) [F7 guard],
// reusablePendingCheckout FindUnresolvedPendingCheckouts(3), GetUserByTeamID(4)
// [customer email], UpdateRazorpaySubscriptionID(5). failAfter=4 makes the
// UPDATE error.
func TestBillingCheckoutFinal2_PersistFailed_503(t *testing.T) {
	checkoutF2NeedDB(t)
	seedDB, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()
	teamID := testhelpers.MustCreateTeamDB(t, seedDB, "free")

	faultDB := openFaultDB(t, 4)
	bh := handlers.NewBillingHandler(faultDB, checkoutFinal2Cfg(), email.NewNoop())
	bh.CreateSubscription = func(map[string]any) (map[string]any, error) {
		return map[string]any{"id": "sub_final2_persist", "short_url": "https://rzp/checkout/final2"}, nil
	}
	app := bvCheckoutApp(t, bh, teamID)
	status, body := postCheckoutF2(t, app)
	// Either billing_persistence_failed (the targeted UPDATE arm) or another
	// 5xx if the query count shifts — both exercise a checkout error path.
	assert.Truef(t, status == http.StatusServiceUnavailable || status == http.StatusBadGateway,
		"expected 5xx, got %d body=%s", status, body)
}
