package handlers_test

// billing_checkout_idempotency_test.go — regression coverage for billing-trust
// audit finding F7 (BILLING-TRUST-AUDIT-2026-05-19.md): a double Razorpay
// subscription / double card charge after a silent first checkout attempt.
//
// THE BUG: CreateCheckoutAPI minted a fresh Razorpay subscription on every
// call, guarded only by a ~60s Redis SETNX. A confused customer whose first
// checkout silently failed and who clicked "Upgrade" again minutes later got a
// SECOND subscription — and once both authorize, both charge the real card.
//
// THE FIX: before minting a new subscription the handler now (a) short-circuits
// when the team already holds the requested tier or higher, and (b) reuses an
// existing still-payable subscription recorded in pending_checkouts instead of
// creating a second one.
//
// These tests run under `go test ./...` — the deploy.yml CI gate. They are
// DB-backed, so they skip cleanly locally when TEST_DATABASE_URL is unset
// (the same billingStateNeedsDB skip pattern the other billing_*_test.go
// files use) and execute in CI where the test DB exists.
//
// WHY THEY FAIL WITHOUT THE FIX: pre-fix CreateCheckoutAPI calls
// CreateSubscription unconditionally. TestCheckout_F7_SecondCall_ReusesLivePendingSubscription
// would see createCalls == 2 (the assertion demands 1) and a different
// subscription_id on the second response.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

// f7CheckoutHarness builds a Fiber app wired to a real BillingHandler with the
// Razorpay create/fetch calls faked. createCalls counts how many times a NEW
// subscription was minted — the F7 assertion that a re-click does not produce
// a second subscription. fetchStatuses maps subscription_id → the status the
// fake Razorpay GET reports.
type f7CheckoutHarness struct {
	app           *fiber.App
	createCalls   *int32
	mintedSubIDs  *[]string
	fetchStatuses map[string]string
}

func newF7CheckoutHarness(t *testing.T, db *sql.DB, teamID string, fetchStatuses map[string]string) *f7CheckoutHarness {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:         testhelpers.TestJWTSecret,
		RazorpayKeyID:     "rzp_test_dummy",
		RazorpayKeySecret: "rzp_test_dummy_secret",
		// Pro monthly plan configured so the requested "pro" checkout resolves
		// a non-empty plan_id and reaches the create/reuse decision.
		RazorpayPlanIDPro: "plan_test_pro_monthly",
	}
	bh := handlers.NewBillingHandler(db, cfg, email.NewNoop())

	var createCalls int32
	minted := make([]string, 0, 2)
	// fetchStatuses is read by the fake Razorpay GET. Newly-minted subscriptions
	// default to "created" (payable) so the reuse probe finds them.
	statuses := fetchStatuses
	if statuses == nil {
		statuses = map[string]string{}
	}

	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		atomic.AddInt32(&createCalls, 1)
		subID := "sub_f7_" + uuid.New().String()
		minted = append(minted, subID)
		statuses[subID] = "created" // freshly minted → still payable
		return map[string]any{
			"id":        subID,
			"short_url": "https://rzp.io/sub/" + subID,
			"status":    "created",
		}, nil
	}
	bh.FetchCheckoutSubscription = func(subID string) (string, string, error) {
		status, ok := statuses[subID]
		if !ok {
			status = "created"
		}
		return status, "https://rzp.io/sub/" + subID, nil
	}

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID)
		return c.Next()
	})
	app.Post("/api/v1/billing/checkout", bh.CreateCheckoutAPI)

	return &f7CheckoutHarness{
		app:           app,
		createCalls:   &createCalls,
		mintedSubIDs:  &minted,
		fetchStatuses: statuses,
	}
}

func (h *f7CheckoutHarness) postCheckout(t *testing.T, plan string) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"plan": plan})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestCheckout_F7_SecondCall_ReusesLivePendingSubscription is the load-bearing
// F7 regression guard. A team with NO existing subscription runs checkout
// twice. The first call mints a subscription; the second — because that
// subscription is still in a payable Razorpay state — must REUSE it: same
// subscription_id, same short_url, and CreateSubscription invoked exactly once
// across both calls. Pre-fix this fails (createCalls == 2, distinct sub IDs).
func TestCheckout_F7_SecondCall_ReusesLivePendingSubscription(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	h := newF7CheckoutHarness(t, db, teamID, nil)

	// First checkout — mints a fresh subscription.
	status1, body1 := h.postCheckout(t, "pro")
	require.Equal(t, http.StatusOK, status1, "first checkout should succeed")
	subID1, _ := body1["subscription_id"].(string)
	shortURL1, _ := body1["short_url"].(string)
	require.NotEmpty(t, subID1, "first checkout must return a subscription_id")
	require.NotEmpty(t, shortURL1, "first checkout must return a short_url")
	require.EqualValues(t, 1, atomic.LoadInt32(h.createCalls),
		"first checkout mints exactly one subscription")

	// Record the pending_checkouts row the production handler writes — the
	// real CreateCheckoutAPI does this via InsertPendingCheckout. We assert it
	// landed so the reuse probe has something to find.
	pending, err := models.FindUnresolvedPendingCheckouts(context.Background(), db, uuid.MustParse(teamID))
	require.NoError(t, err)
	require.Len(t, pending, 1, "first checkout must record an unresolved pending_checkouts row")
	require.Equal(t, subID1, pending[0].SubscriptionID)

	// Second checkout — the confused-re-click. Must reuse, NOT mint a second.
	status2, body2 := h.postCheckout(t, "pro")
	require.Equal(t, http.StatusOK, status2, "second checkout should succeed by reuse")
	subID2, _ := body2["subscription_id"].(string)
	shortURL2, _ := body2["short_url"].(string)

	assert.Equal(t, subID1, subID2,
		"F7: second checkout must return the SAME subscription_id, not mint a new one")
	assert.Equal(t, shortURL1, shortURL2,
		"F7: second checkout must return the SAME short_url")
	assert.Equal(t, true, body2["reused"],
		"F7: a reused checkout response is flagged reused:true")
	assert.EqualValues(t, 1, atomic.LoadInt32(h.createCalls),
		"F7: CreateSubscription must be invoked EXACTLY ONCE across both checkout calls — a second subscription would double-charge the customer's card")
	assert.Len(t, *h.mintedSubIDs, 1,
		"F7: exactly one Razorpay subscription minted for the team")
}

// TestCheckout_F7_DeadPendingSubscription_MintsNewSubscription is the negative
// control: when the only pending_checkouts row points at a subscription
// Razorpay reports as terminal (cancelled), there is nothing to reuse, so a
// NEW subscription IS minted. This proves the F7 guard reuses only LIVE
// subscriptions and never wedges a legitimate fresh checkout.
func TestCheckout_F7_DeadPendingSubscription_MintsNewSubscription(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	teamID := testhelpers.MustCreateTeamDB(t, db, "free")
	teamUUID := uuid.MustParse(teamID)

	// Seed a stale pending_checkouts row whose subscription Razorpay treats as
	// cancelled — the customer abandoned it and it can never be completed.
	deadSubID := "sub_f7_dead_" + uuid.New().String()
	require.NoError(t, models.InsertPendingCheckout(
		context.Background(), db, deadSubID, teamUUID, "", "pro"))

	h := newF7CheckoutHarness(t, db, teamID, map[string]string{
		deadSubID: "cancelled",
	})

	status, body := h.postCheckout(t, "pro")
	require.Equal(t, http.StatusOK, status, "checkout should succeed with a fresh subscription")
	newSubID, _ := body["subscription_id"].(string)

	assert.NotEqual(t, deadSubID, newSubID,
		"a cancelled (terminal) pending subscription must NOT be reused")
	assert.NotEmpty(t, newSubID, "a fresh subscription_id must be returned")
	assert.Nil(t, body["reused"],
		"a freshly-minted checkout is not flagged reused")
	assert.EqualValues(t, 1, atomic.LoadInt32(h.createCalls),
		"a NEW subscription must be minted when no live reusable one exists")
}

// TestCheckout_F7_AlreadyOnTier_ShortCircuits verifies the already-paid
// short-circuit: a team already on the requested tier (or higher) must NOT get
// a checkout at all — it returns 400 already_on_plan and mints nothing. A
// customer already paying for Pro who re-clicks "Upgrade to Pro" must not be
// sold the plan twice.
func TestCheckout_F7_AlreadyOnTier_ShortCircuits(t *testing.T) {
	db, cleanup := billingStateNeedsDB(t)
	defer cleanup()

	// Team is already on pro — the requested checkout tier.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")
	h := newF7CheckoutHarness(t, db, teamID, nil)

	status, body := h.postCheckout(t, "pro")

	assert.Equal(t, http.StatusBadRequest, status,
		"a checkout for a tier the team already holds must be rejected")
	assert.Equal(t, "already_on_plan", body["error"],
		"the rejection uses the already_on_plan error code")
	assert.EqualValues(t, 0, atomic.LoadInt32(h.createCalls),
		"no Razorpay subscription may be minted when the team is already on the requested tier")
}
