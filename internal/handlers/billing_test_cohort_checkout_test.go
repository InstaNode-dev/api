// billing_test_cohort_checkout_test.go — Wave 4b coverage for the synthetic
// test-cohort → rzp_test_* checkout routing
// (docs/ci/01-CI-INTEGRATION-DESIGN.md §"Razorpay test-card payment E2E").
//
// The CEO ask: CI must drive a REAL test-card payment (free user → upgrade →
// Razorpay TEST hosted-checkout → test card → Pro active) with NO real money.
// To do that the api routes a cohort team's checkout through the rzp_test_*
// credentials (test mode has no live-recurring approval gate), while the LIVE
// billing path stays untouched.
//
// Routing contract (all enforced here):
//   - cohort team + test keys+plan configured → checkout uses the TEST key +
//     TEST plan_id; the live-key guards are bypassed; response still hides keys.
//   - cohort team + test keys UNSET → INERT: falls back to the existing
//     synthetic_test_cohort skip (403), live path never touched, no crash.
//   - cohort team + test keys set but NO test plan for the tier → INERT skip.
//   - NON-cohort team → ALWAYS the live path, regardless of test-key config.
//   - webhook verifies the TEST webhook secret (try-both: live first, then test).
//
// The pure-function inert proofs (testModeConfigured / razorpayTestPlanIDFor)
// run with NO DB so they execute in every CI run; the full routing tests are
// DB-gated (cov2NeedsDB) like the rest of the checkout suite.
package handlers_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// fixture test-mode creds — non-secret, prefix is the only load-bearing part.
const (
	testCohortKeyID         = "rzp_test_0cohortfixture" //nolint:gosec // fixture, not a credential
	testCohortKeySecret     = "test-cohort-secret-fixture"
	testCohortWebhookSecret = "test-cohort-webhook-secret-fixture"
	testCohortPlanPro       = "plan_test_pro_fixture"
)

// ── Pure-function inert proofs (NO DB — always run in CI) ────────────────────

// TestTestModeConfigured_InertWhenUnset proves the whole test-mode path is
// INERT when the operator has not wired the rzp_test_* key+secret. This is the
// "default empty = inert" guarantee: on prod (no test keys) the cohort routing
// never engages, so live billing is provably untouched.
func TestTestModeConfigured_InertWhenUnset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		cfg    config.Config
		expect bool
	}{
		{"both unset", config.Config{}, false},
		{"only id set", config.Config{RazorpayTestKeyID: testCohortKeyID}, false},
		{"only secret set", config.Config{RazorpayTestKeySecret: testCohortKeySecret}, false},
		{"both set → configured", config.Config{RazorpayTestKeyID: testCohortKeyID, RazorpayTestKeySecret: testCohortKeySecret}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := tc.cfg
			bh := handlers.NewBillingHandler(nil, &cfg, nil)
			assert.Equal(t, tc.expect, handlers.ExerciseTestModeConfigured(bh))
		})
	}
}

// TestRazorpayTestPlanIDFor_OnlySelfServeTiers proves only the self-serve
// checkout tiers (hobby/hobby_plus/pro) resolve a test plan_id; growth/team and
// junk return "" so a cohort checkout for those tiers falls back to inert.
func TestRazorpayTestPlanIDFor_OnlySelfServeTiers(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		RazorpayTestPlanIDHobby:     "p_hobby",
		RazorpayTestPlanIDHobbyPlus: "p_hobby_plus",
		RazorpayTestPlanIDPro:       "p_pro",
	}
	bh := handlers.NewBillingHandler(nil, &cfg, nil)
	assert.Equal(t, "p_hobby", handlers.ExerciseRazorpayTestPlanIDFor(bh, "hobby"))
	assert.Equal(t, "p_hobby_plus", handlers.ExerciseRazorpayTestPlanIDFor(bh, "hobby_plus"))
	assert.Equal(t, "p_pro", handlers.ExerciseRazorpayTestPlanIDFor(bh, "pro"))
	assert.Equal(t, "", handlers.ExerciseRazorpayTestPlanIDFor(bh, "growth"))
	assert.Equal(t, "", handlers.ExerciseRazorpayTestPlanIDFor(bh, "team"))
	assert.Equal(t, "", handlers.ExerciseRazorpayTestPlanIDFor(bh, "nonsense"))
}

// TestCreateSubscription_TestModeDefaultClosure exercises the PRODUCTION
// default CreateSubscription closure with the private test-mode flag set, so
// the rzp_test_* key-swap + flag-strip branch runs (no DB; the unconfigured
// Razorpay call errors out, which is fine — we only need the closure body to
// execute). Pairs with the non-flag ExerciseCreateSubscription.
func TestCreateSubscription_TestModeDefaultClosure(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{RazorpayTestKeyID: testCohortKeyID, RazorpayTestKeySecret: testCohortKeySecret}
	bh := handlers.NewBillingHandler(nil, cfg, nil)
	handlers.ExerciseCreateSubscriptionTestMode(bh) // must not panic
}

// TestResolveCheckoutTestMode_FailsClosedOnDBError proves the is_test_cohort
// lookup error path returns useTest=false (fail CLOSED) so a DB blip never
// routes a real customer through the test account. A closed *sql.DB makes
// IsTestCohort return an error.
func TestResolveCheckoutTestMode_FailsClosedOnDBError(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	cfg := &config.Config{RazorpayTestKeyID: testCohortKeyID, RazorpayTestKeySecret: testCohortKeySecret, RazorpayTestPlanIDPro: testCohortPlanPro}
	bh := handlers.NewBillingHandler(db, cfg, nil)
	clean() // close the DB so IsTestCohort errors
	useTest, planID := handlers.ExerciseResolveCheckoutTestMode(bh, context.Background(), uuid.New(), "pro")
	assert.False(t, useTest, "a DB error on is_test_cohort must fail CLOSED (live path)")
	assert.Equal(t, "", planID)
}

// ── Full routing tests (DB-gated) ────────────────────────────────────────────

// TestCohortCheckout_UsesTestKeyAndPlan is the core Wave 4b proof: a cohort
// team with test keys+plan configured mints a subscription through the TEST
// credentials (asserted by capturing the plan_id the CreateSubscription closure
// receives — it must be the TEST plan, not the live one) and the private
// test-mode flag must be set on the body. The live-key-in-dev guard is bypassed
// even though the deployment is "development" + a live key is present.
func TestCohortCheckout_UsesTestKeyAndPlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		// Live key on a dev deployment would normally 503 via the BUG-P112
		// guard — the test-mode path MUST bypass it for cohort teams.
		Environment:           "development",
		RazorpayKeyID:         liveKeyExample,
		RazorpayKeySecret:     "live-secret-fixture",
		RazorpayPlanIDPro:     "plan_LIVE_pro",
		RazorpayTestKeyID:     testCohortKeyID,
		RazorpayTestKeySecret: testCohortKeySecret,
		RazorpayTestPlanIDPro: testCohortPlanPro,
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	require.NoError(t, models.SetTestCohort(context.Background(), db, uuid.MustParse(teamID), true))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	var gotPlanID string
	var gotTestFlag bool
	bh.CreateSubscription = func(body map[string]any) (map[string]any, error) {
		gotPlanID, _ = body["plan_id"].(string)
		gotTestFlag, _ = body[handlers.SubBodyTestModeKeyForTest].(bool)
		return map[string]any{"id": "sub_test_cohort_" + uuid.NewString(), "short_url": "https://rzp.io/test"}, nil
	}
	status, respBody := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, status, "cohort+test-keys must succeed, body=%v", respBody)
	assert.Equal(t, testCohortPlanPro, gotPlanID, "must mint against the TEST plan_id, not the live one")
	assert.True(t, gotTestFlag, "the private test-mode flag must be set so the closure picks test creds")
	assert.NotNil(t, respBody["short_url"])
	// Key-leak contract holds on the test path too.
	raw, _ := json.Marshal(respBody)
	assert.NotContains(t, string(raw), testCohortKeyID)
	assert.NotContains(t, string(raw), liveKeyExample)
}

// TestCohortCheckout_InertWhenTestKeysUnset proves the inert fallback: a cohort
// team with NO test keys configured hits the existing synthetic_test_cohort
// skip (403) and NEVER reaches CreateSubscription — no crash, live path safe.
func TestCohortCheckout_InertWhenTestKeysUnset(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		Environment:       "production",
		RazorpayKeyID:     liveKeyExample,
		RazorpayKeySecret: "live-secret-fixture",
		RazorpayPlanIDPro: "plan_LIVE_pro",
		// No RazorpayTest* — test mode inert.
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	require.NoError(t, models.SetTestCohort(context.Background(), db, uuid.MustParse(teamID), true))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return nil, assertingError("inert cohort path must NOT mint a subscription")
	}
	status, respBody := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusForbidden, status, "inert cohort must 403-skip, body=%v", respBody)
	assert.Equal(t, "synthetic_test_cohort", respBody["error"])
}

// TestCohortCheckout_InertWhenTierHasNoTestPlan proves partial config (test
// keys set, but no test plan for the requested tier) falls back to the inert
// skip rather than minting against the LIVE plan.
func TestCohortCheckout_InertWhenTierHasNoTestPlan(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		Environment:           "production",
		RazorpayKeyID:         liveKeyExample,
		RazorpayKeySecret:     "live-secret-fixture",
		RazorpayPlanIDPro:     "plan_LIVE_pro",
		RazorpayTestKeyID:     testCohortKeyID,
		RazorpayTestKeySecret: testCohortKeySecret,
		// RazorpayTestPlanIDPro intentionally UNSET → no test plan for pro.
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	require.NoError(t, models.SetTestCohort(context.Background(), db, uuid.MustParse(teamID), true))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return nil, assertingError("partial-config cohort must NOT mint against the live plan")
	}
	status, respBody := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusForbidden, status, "partial-config cohort must 403-skip, body=%v", respBody)
	assert.Equal(t, "synthetic_test_cohort", respBody["error"])
}

// TestNonCohortCheckout_AlwaysLivePath proves a NON-cohort team always uses the
// LIVE key+plan even when test keys are fully configured — live billing is
// provably unaffected by the test-mode wiring.
func TestNonCohortCheckout_AlwaysLivePath(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:             "test-secret-that-is-at-least-32-bytes-long!!",
		Environment:           "production",
		RazorpayKeyID:         liveKeyExample,
		RazorpayKeySecret:     "live-secret-fixture",
		RazorpayPlanIDPro:     "plan_LIVE_pro",
		RazorpayTestKeyID:     testCohortKeyID,
		RazorpayTestKeySecret: testCohortKeySecret,
		RazorpayTestPlanIDPro: testCohortPlanPro,
	}
	// NOT a cohort team — default is_test_cohort=false.
	teamID, userID := seedVerifiedTeamUser(t, db, "free")

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	var gotPlanID string
	var gotTestFlag bool
	bh.CreateSubscription = func(body map[string]any) (map[string]any, error) {
		gotPlanID, _ = body["plan_id"].(string)
		gotTestFlag, _ = body[handlers.SubBodyTestModeKeyForTest].(bool)
		return map[string]any{"id": "sub_live_" + uuid.NewString(), "short_url": "https://rzp.io/live"}, nil
	}
	status, respBody := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, status, "non-cohort must use live path, body=%v", respBody)
	assert.Equal(t, "plan_LIVE_pro", gotPlanID, "non-cohort must mint against the LIVE plan_id")
	assert.False(t, gotTestFlag, "non-cohort must NOT carry the test-mode flag")
	assert.Equal(t, "production", respBody["traffic_env"])
}

// ── Webhook try-both verification ─────────────────────────────────────────────

// signRzp produces the X-Razorpay-Signature for a body under a secret
// (hex(HMAC-SHA256(body, secret)) — no timestamp prefix, matches the verifier).
func signRzp(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// nowUnixStr is the current Unix second as a string, so the body's created_at
// is always inside the ±5min replay window.
func nowUnixStr() string { return strconv.FormatInt(time.Now().Unix(), 10) }

// newRzpWebhookApp wires a Fiber app with just the webhook route. No DB is
// needed for the signature-verification leg under test (an unrecognised event
// type hits the switch default → 200 without touching the DB).
func newRzpWebhookApp(bh *handlers.BillingHandler) *fiber.App {
	// cov2ErrHandler mirrors production: a respond* helper writes the response
	// then returns ErrResponseWritten, which the error handler must treat as a
	// no-op (default Fiber would turn it into a 500). Without this a 400
	// signature-mismatch surfaces as 500.
	app := fiber.New(fiber.Config{ErrorHandler: cov2ErrHandler})
	app.Use(middleware.RequestID())
	app.Post("/razorpay/webhook", bh.RazorpayWebhook)
	return app
}

// postWebhook POSTs a signed body and returns the status code.
func postRzpWebhook(t *testing.T, app *fiber.App, body []byte, sig string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/razorpay/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Razorpay-Signature", sig)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestWebhook_VerifiesTestSecret proves the try-both verification: a payload
// signed with the TEST webhook secret is accepted (so a real test-mode event
// upgrades a cohort team), while live webhooks remain accepted under the live
// secret and a wrong signature is still rejected 400.
func TestWebhook_VerifiesTestSecret(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{
		RazorpayWebhookSecret:     "live-webhook-secret",
		RazorpayTestWebhookSecret: testCohortWebhookSecret,
	}
	bh := handlers.NewBillingHandler(nil, cfg, nil)
	app := newRzpWebhookApp(bh)

	// An unrecognised event type verifies the signature but is a no-op handler
	// → still 200 (Razorpay must see 2xx). The point here is the SIGNATURE leg.
	body := []byte(`{"event":"order.paid","created_at":` + nowUnixStr() + `,"id":"evt_test_4b"}`)

	t.Run("test secret accepted", func(t *testing.T) {
		status := postRzpWebhook(t, app, body, signRzp(body, testCohortWebhookSecret))
		assert.Equal(t, http.StatusOK, status, "a payload signed with the TEST webhook secret must verify")
	})
	t.Run("live secret still accepted", func(t *testing.T) {
		status := postRzpWebhook(t, app, body, signRzp(body, "live-webhook-secret"))
		assert.Equal(t, http.StatusOK, status, "live webhook secret must still verify")
	})
	t.Run("wrong secret rejected", func(t *testing.T) {
		status := postRzpWebhook(t, app, body, signRzp(body, "totally-wrong-secret"))
		assert.Equal(t, http.StatusBadRequest, status, "a signature under neither secret must be rejected 400")
	})
}

// TestWebhook_TestSecretInertWhenUnset proves that with no test webhook secret
// configured, only the live secret verifies (no accidental acceptance).
func TestWebhook_TestSecretInertWhenUnset(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{RazorpayWebhookSecret: "live-webhook-secret"} // no test secret
	bh := handlers.NewBillingHandler(nil, cfg, nil)
	app := newRzpWebhookApp(bh)
	body := []byte(`{"event":"order.paid","created_at":` + nowUnixStr() + `,"id":"evt_inert_4b"}`)

	assert.Equal(t, http.StatusOK, postRzpWebhook(t, app, body, signRzp(body, "live-webhook-secret")))
	assert.Equal(t, http.StatusBadRequest, postRzpWebhook(t, app, body, signRzp(body, testCohortWebhookSecret)),
		"with no test secret configured, the test-secret leg must be inert")
}
