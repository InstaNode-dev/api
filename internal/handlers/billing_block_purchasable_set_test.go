package handlers_test

// billing_block_purchasable_set_test.go — W3 (Billing block integration tests).
//
// The single most revenue-critical invariant of the billing block is which
// tiers a team can self-serve PURCHASE through POST /api/v1/billing/checkout.
// The §E3 hard gate (shipped in #245, 2026-06-04 CEO directive) is that the
// Team plan ($199 "unlimited") is NOT rolled out and must never be reachable
// by a self-serve charge until its unlimited-resource delivery is proven
// built. Memory: project_team_plan_not_rolled_out_no_payment.
//
// The danger is not just "team is gated today" — it is "a NEW tier added to
// plans.yaml tomorrow silently becomes purchasable" (the registry-drift bug
// class, rule 18). A hand-typed allowlist would itself be a single-site
// fallacy. So this suite drives EVERY tier in the live plans.Registry through
// the REAL CreateCheckoutAPI handler and asserts the set of tiers the handler
// accepts (reaches CreateSubscription for) is EXACTLY {hobby, hobby_plus,
// pro}. Add a tier to plans.yaml without wiring it into the checkout switch and
// this test reds; re-enable Team checkout and this test reds.
//
// Real-backend integration test: each tier is exercised against a real test
// Postgres team row (TEST_DATABASE_URL) so the email-verify gate, the
// already-on-tier guard, and the team-gate all run on real data. The Razorpay
// CreateSubscription call is the ONLY fake — it must never reach a real
// Razorpay account.

import (
	"net/http"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/plans"
)

// selfServePurchasableTiers is the EXACT set of canonical tiers a team may
// purchase via self-serve checkout, per the 2026-06-04 CEO directive. It is
// the EXPECTED value the registry-iterating test asserts the handler's actual
// behaviour against — it is NOT consulted by any production code path. If this
// list and the live handler ever disagree, one of them is wrong; the test
// makes that a red, not a silent revenue bug.
//
//   - hobby      ($9)   — purchasable
//   - hobby_plus ($19)  — purchasable
//   - pro        ($49)  — purchasable
//   - growth     ($99)  — NOT self-serve via checkout (sales-assisted; the
//     checkout switch rejects it as invalid_plan today)
//   - team       ($199) — HARD-GATED: tier_not_yet_available (§E3)
//   - anonymous/free    — not chargeable tiers at all
var selfServePurchasableTiers = []string{"hobby", "hobby_plus", "pro"}

// checkoutClassification is the observed outcome of driving one tier through
// the real CreateCheckoutAPI handler.
type checkoutClassification struct {
	tier            string
	httpStatus      int
	errorCode       string // "" when the handler accepted the checkout
	reachedRazorpay bool
}

// TestBillingBlock_SelfServePurchasableSet_IsExactlyHobbyHobbyPlusPro is the
// W3 headline assertion. It iterates the LIVE plans.Registry (no hand-typed
// tier list drives the loop), canonicalises each tier, and drives it through
// the production CreateCheckoutAPI handler with a real verified team. It then
// asserts the set of tiers the handler ACCEPTS (reaches the Razorpay
// CreateSubscription seam) equals selfServePurchasableTiers exactly.
//
// Why registry-iterating (rule 18): the failure mode this guards is "someone
// adds 'starter' to plans.yaml and forgets the checkout switch, making it
// either silently purchasable or silently 500." Driving the registry, not a
// fixed slice, makes the new tier appear in the loop automatically.
func TestBillingBlock_SelfServePurchasableSet_IsExactlyHobbyHobbyPlusPro(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}

	reg := plans.Default()
	require.NotNil(t, reg, "plans.Default() must return a registry")

	// Collect the distinct canonical tiers from the live registry. Yearly
	// variants (hobby_yearly, pro_yearly, …) canonicalise onto their base
	// tier so we test each tier identity once.
	canonicalSet := map[string]struct{}{}
	for rawTier := range reg.All() {
		canonicalSet[plans.CanonicalTier(rawTier)] = struct{}{}
	}
	require.NotEmpty(t, canonicalSet, "registry must expose at least one tier")
	// Sanity: the registry MUST contain the gated tier — otherwise the test
	// would pass vacuously (no Team row to gate).
	_, hasTeam := canonicalSet["team"]
	require.True(t, hasTeam,
		"plans.Registry must contain the 'team' tier — the §E3 gate is meaningless if Team is absent from the registry")

	classifications := make([]checkoutClassification, 0, len(canonicalSet))
	for tier := range canonicalSet {
		classifications = append(classifications, classifyCheckoutTier(t, tier))
	}

	// Build the ACTUAL purchasable set from the handler's behaviour.
	var actualPurchasable []string
	for _, cl := range classifications {
		if cl.reachedRazorpay {
			actualPurchasable = append(actualPurchasable, cl.tier)
		}
	}
	sort.Strings(actualPurchasable)
	want := append([]string(nil), selfServePurchasableTiers...)
	sort.Strings(want)

	assert.Equal(t, want, actualPurchasable,
		"the self-serve purchasable tier set (tiers that reach the Razorpay CreateSubscription seam) must be EXACTLY %v — "+
			"a new tier here means a tier became chargeable without review; a missing tier means a paid tier stopped being purchasable. "+
			"per-tier outcomes: %+v", want, classifications)

	// Explicit §E3 belt: Team must be rejected with the DISTINCT
	// tier_not_yet_available code (not the generic invalid_plan), so the SPA
	// renders "contact sales / not yet available" rather than "you made a
	// typo". This is asserted separately from the set so a regression that
	// changed only the error CODE (still rejecting, but with the wrong code)
	// is caught.
	for _, cl := range classifications {
		if cl.tier != "team" {
			continue
		}
		assert.False(t, cl.reachedRazorpay,
			"Team checkout must NEVER reach Razorpay CreateSubscription (§E3 hard gate)")
		assert.Equal(t, http.StatusBadRequest, cl.httpStatus,
			"Team checkout must be a 400, not a 5xx — a misconfigured gate that 500s is still a bug")
		assert.Equal(t, "tier_not_yet_available", cl.errorCode,
			"Team checkout must return the distinct 'tier_not_yet_available' code so the SPA shows the contact-sales copy")
	}
}

// classifyCheckoutTier drives a single canonical tier through the real
// CreateCheckoutAPI handler with a fresh verified FREE team (so no
// already-on-tier short-circuit fires for any paid tier) and a fully
// configured Razorpay cfg (key + secret + every paid tier's plan_id), then
// reports whether the handler reached the Razorpay CreateSubscription seam.
//
// CreateSubscription is faked to set reachedRazorpay=true and return a valid
// subscription — it must NEVER hit a real Razorpay account. A tier that is
// gated/invalid is rejected BEFORE this fake is called, so reachedRazorpay
// stays false for non-purchasable tiers.
func classifyCheckoutTier(t *testing.T, tier string) checkoutClassification {
	t.Helper()
	db, clean := billingBlockDB(t)
	defer clean()

	// Configure plan_ids for every paid tier so the only thing that can stop
	// a checkout from reaching Razorpay is the handler's own gate logic, NOT a
	// missing plan_id (which would yield a false "not purchasable" via the
	// billing_not_configured branch). The live-key guard is avoided by using a
	// rzp_test_* style key with Environment="production" so no misconfig fires.
	cfg := &config.Config{
		JWTSecret:               billingBlockJWTSecret,
		Environment:             "production",
		RazorpayKeyID:           "rzp_test_blockfixturekey",
		RazorpayKeySecret:       "secret",
		RazorpayPlanIDHobby:     "plan_hobby",
		RazorpayPlanIDHobbyPlus: "plan_hobby_plus",
		RazorpayPlanIDPro:       "plan_pro",
		RazorpayPlanIDGrowth:    "plan_growth",
		RazorpayPlanIDTeam:      "plan_team",
	}

	// A fresh FREE team: rank 1, below every paid tier, so the already-on-tier
	// guard never short-circuits a paid-tier checkout.
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)

	reached := false
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		reached = true
		return map[string]any{
			"id":        "sub_block_" + uuid.NewString(),
			"short_url": "https://rzp.example/checkout",
		}, nil
	}

	status, body := postCheckoutReq(t, app, map[string]any{"plan": tier})
	errCode, _ := body["error"].(string)
	return checkoutClassification{
		tier:            tier,
		httpStatus:      status,
		errorCode:       errCode,
		reachedRazorpay: reached,
	}
}

// TestBillingBlock_ChangePlanPurchasableSet_RejectsTeamAndUnknown mirrors the
// purchasable-set invariant for the in-app change-plan path: an existing
// paying team trying to MOVE to Team must hit the same §E3 gate
// (tier_not_yet_available), and an unknown/non-purchasable target must be
// rejected. This complements the checkout set above — Team must be unreachable
// from BOTH self-serve charge-initiation surfaces.
func TestBillingBlock_ChangePlanPurchasableSet_RejectsTeamAndUnknown(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}

	cases := []struct {
		name      string
		startTier string
		target    string
		wantCode  string
	}{
		{"team is gated from change-plan", "hobby", "team", "tier_not_yet_available"},
		{"growth is not self-serve via change-plan", "hobby", "growth", "invalid_plan"},
		{"unknown tier rejected", "hobby", "definitely_not_a_tier", "invalid_plan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, clean := billingBlockDB(t)
			defer clean()
			teamID := mustSeedTeam(t, db, tc.startTier)
			cfg := &config.Config{
				JWTSecret:          billingBlockJWTSecret,
				RazorpayKeyID:      "rzp_test_k",
				RazorpayKeySecret:  "s",
				RazorpayPlanIDPro:  "plan_pro",
				RazorpayPlanIDTeam: "plan_team",
			}
			app := changePlanAppReal(t, db, cfg, teamID)
			code, body := changePlanReq(t, app, map[string]any{"target_plan": tc.target})
			assert.Equal(t, http.StatusBadRequest, code, "body=%v", body)
			assert.Equal(t, tc.wantCode, body["error"],
				"change-plan target=%q must be rejected with %q (body=%v)", tc.target, tc.wantCode, body)
		})
	}
}
