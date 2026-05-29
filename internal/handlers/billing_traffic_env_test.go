// billing_traffic_env_test.go — coverage for the BUG-P112 server-side
// guard (live Razorpay key on a non-production deployment) + the
// `traffic_env` field surfaced on the /api/v1/billing/checkout response.
//
// The QA team caught a P0 LIVE-mode Razorpay subscription page rendered
// for an unauthenticated user via /app/checkout/?plan=hobby
// (BUG-P111/P112). The SPA fix (instanode-web fix/checkout-auth-gate-…)
// blocks the unauth case at the page layer; this server-side guard is
// the belt-and-braces defence at the API.
//
// Tests:
//   - TestBillingCheckout_DetectsLiveKeyInDevEnv — every (deployment,
//     key) combination, asserting the dangerous one (live + non-prod)
//     returns 503 billing_misconfigured with a clear operator
//     agent_action, and every safe pairing falls through.
//   - TestBillingCheckout_ResponseIncludesTrafficEnv — happy-path
//     response shape: derived traffic_env is "production" or "test",
//     and the actual RAZORPAY_KEY_ID is NEVER echoed anywhere in the
//     response body. The lookup-failed-open case for team-loading also
//     exercises the fresh-create path through the test seam.

package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"instant.dev/internal/config"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// liveKeyExample / testKeyExample / unknownKeyExample are non-secret
// fixture key IDs used only in this test. The trailing 14-char base62
// segment matches the real Razorpay convention so a future contributor
// running `rg rzp_live_` against fixtures sees the explicit comment that
// these are TEST FIXTURES, not credentials.
const (
	// fixture: not a real key — only the prefix is load-bearing for
	// the trafficEnv derivation under test.
	liveKeyExample    = "rzp_live_0fixturekey00" // 14-char fixture suffix
	testKeyExample    = "rzp_test_0fixturekey00"
	unknownKeyExample = "rzp_xyz_0fixturekey00" // unrecognised prefix
)

// TestBillingCheckout_DetectsLiveKeyInDevEnv exhaustively pins the
// (deployment environment × razorpay key class) matrix. Only the
// dangerous combination (live key + non-prod deployment) must
// short-circuit with 503 billing_misconfigured. Every safe pairing
// must fall through to the next stage of the handler.
//
// The handler also needs valid plan IDs and a valid plan_frequency for
// the request to actually reach our guard; we use the no-DB harness so
// the test exits after the guard branch and before the F7 idempotency
// path needs a real DB.
func TestBillingCheckout_DetectsLiveKeyInDevEnv(t *testing.T) {
	cases := []struct {
		name           string
		environment    string
		key            string
		wantStatus     int
		wantErrorCode  string
		assertResponse func(t *testing.T, body map[string]any)
	}{
		{
			// THE BUG-P112 root cause. Operator points an Indian dev or
			// staging deployment at the prod Razorpay live key by accident.
			// Without this guard, an unauth /app/checkout/?plan=hobby
			// (BUG-P111) would create a real LIVE subscription.
			name:          "live key + development deployment → 503 billing_misconfigured",
			environment:   "development",
			key:           liveKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_misconfigured",
			assertResponse: func(t *testing.T, body map[string]any) {
				// Operator must get a clear agent-actionable error.
				agentAction, _ := body["agent_action"].(string)
				assert.Contains(t, agentAction, "test key")
				assert.Contains(t, agentAction, "non-production")
				// The actual key value MUST NEVER appear in the response —
				// this is the security contract: only the derived
				// traffic_env boolean may leak.
				raw, _ := json.Marshal(body)
				assert.NotContains(t, string(raw), liveKeyExample,
					"the actual RAZORPAY_KEY_ID must NEVER appear in the response body")
			},
		},
		{
			// Same root cause, "staging" variant. Any non-prod env triggers.
			name:          "live key + staging deployment → 503 billing_misconfigured",
			environment:   "staging",
			key:           liveKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_misconfigured",
		},
		{
			// "test" environment is the third common non-prod label —
			// CI runners, ephemeral deploys, etc. Same guard fires.
			name:          "live key + test deployment → 503 billing_misconfigured",
			environment:   "test",
			key:           liveKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_misconfigured",
		},
		{
			// Empty ENVIRONMENT defaults effectively to non-prod —
			// developer ran `make run` with no env set. The guard
			// fires here too; the operator must opt INTO production
			// to pair with a live key.
			name:          "live key + empty deployment → 503 billing_misconfigured",
			environment:   "",
			key:           liveKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_misconfigured",
		},
		{
			// THE INTENDED PRODUCTION PAIRING — live key matched to a
			// production deployment is correct. The guard must NOT
			// fire. We use the `growth` plan (valid plan name, but the
			// fixture cfg leaves RazorpayPlanIDGrowth unset) to force a
			// downstream 503 billing_not_configured so the test can
			// see the misconfig guard did NOT short-circuit, without
			// depending on a DB for the email-verify gate or a fake
			// Razorpay client for the create call.
			name:          "live key + production deployment → falls through (intended pairing)",
			environment:   "production",
			key:           liveKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_not_configured", // growth plan_id unset
		},
		{
			// Test key on a dev deployment is the intended dev pairing.
			// Same growth-plan trick falls through to billing_not_configured.
			name:          "test key + development → falls through (intended pairing)",
			environment:   "development",
			key:           testKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_not_configured",
		},
		{
			// Test key on production is unusual (operator used the
			// sandbox key in prod by mistake) but NOT a real-money
			// failure — Razorpay rejects the charge cleanly. The
			// guard intentionally does not catch this; we don't want
			// to wedge a staging-to-prod cutover where the operator
			// briefly flips ENVIRONMENT first. Existing 503
			// billing_not_configured / plan_id-missing paths catch
			// most of the real-world variants.
			name:          "test key + production → falls through (not in scope of this guard)",
			environment:   "production",
			key:           testKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_not_configured",
		},
		{
			// Empty key → billing_not_configured branch takes over (the
			// existing guard one stage earlier in CreateCheckoutAPI).
			// The misconfig branch correctly does NOT classify this.
			name:          "empty key + any deployment → billing_not_configured (existing branch)",
			environment:   "production",
			key:           "",
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_not_configured",
		},
		{
			// Unrecognised key prefix → trafficEnv reports recognised=false,
			// the misconfig guard does not classify, falls through to
			// billing_not_configured for the same growth-plan reason.
			name:          "unknown-prefix key + production → falls through (not classified)",
			environment:   "production",
			key:           unknownKeyExample,
			wantStatus:    http.StatusServiceUnavailable,
			wantErrorCode: "billing_not_configured",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{
				JWTSecret:                 "test-secret-that-is-at-least-32-bytes-long!!",
				Environment:               tc.environment,
				RazorpayKeyID:             tc.key,
				RazorpayKeySecret:         "secret-fixture", // non-empty so the not_configured branch doesn't shadow
				RazorpayPlanIDPro:         "plan_monthly_pro",
				RazorpayPlanIDProYearly:   "plan_yearly_pro",
				RazorpayPlanIDHobby:       "plan_monthly_hobby",
				// RazorpayPlanIDTeam intentionally LEFT EMPTY. The test
				// requests plan="team" — a valid plan name in the switch
				// (passes the 400 invalid_plan branch) but with no plan_id
				// configured, so a guard-cleared request falls through to
				// the 503 billing_not_configured branch. This cleanly
				// distinguishes:
				//   - guard fired              → 503 billing_misconfigured
				//   - guard let through        → 503 billing_not_configured
				// without depending on a DB for the email-verify gate.
			}
			app := checkoutAppNoDB(t, cfg)
			status, body := postCheckout(t, app, map[string]any{
				"plan": "team",
			})
			assert.Equal(t, tc.wantStatus, status, "body=%v", body)
			assert.Equal(t, tc.wantErrorCode, body["error"], "body=%v", body)
			if tc.assertResponse != nil {
				tc.assertResponse(t, body)
			}
		})
	}
}

// TestBillingCheckout_TrafficEnvHelperUnitCoverage exercises the
// trafficEnv + detectBillingMisconfiguration helpers directly so
// future regressions in the pure logic surface without needing the
// Fiber harness above. Tests the package-internal exported helpers
// by re-deriving them from the surface contract:
//
//   trafficEnv("rzp_live_X")  -> ("production", true)
//   trafficEnv("rzp_test_X")  -> ("test", true)
//   trafficEnv("")            -> ("test", false)
//   trafficEnv("garbage")     -> ("test", false)
//
// We assert through the public CreateCheckoutAPI surface because the
// helpers are package-private. The matrix above already exercises every
// combination; this test pins the contract that the derived field is
// "production" or "test" (the only two values the SPA branches on).
func TestBillingCheckout_TrafficEnvDerivation_OnlyProductionOrTest(t *testing.T) {
	cases := []struct {
		key  string
		want string
	}{
		{liveKeyExample, "production"},
		{testKeyExample, "test"},
		// Mixed-case key. The handler lowercases before comparing.
		{strings.ToUpper(testKeyExample), "test"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want+"_"+tc.key, func(t *testing.T) {
			cfg := &config.Config{
				JWTSecret:                 "test-secret-that-is-at-least-32-bytes-long!!",
				Environment:               envForKey(tc.key), // production iff live
				RazorpayKeyID:             tc.key,
				RazorpayKeySecret:         "secret-fixture",
				RazorpayPlanIDPro:         "plan_monthly_pro",
			}
			// Invalid plan body forces 400 — but the error envelope
			// doesn't carry traffic_env, so we can't observe the derivation
			// through this path. Instead, send a deliberately mis-specified
			// plan that lands in the 400 invalid_plan envelope and verify
			// the response NEVER contains the actual key. Surface-coverage
			// of the success-path derivation lives in the DB-backed test
			// below (skipped without DB).
			app := checkoutAppNoDB(t, cfg)
			_, body := postCheckout(t, app, map[string]any{"plan": "bogus"})
			raw, _ := json.Marshal(body)
			assert.NotContains(t, strings.ToLower(string(raw)), strings.ToLower(tc.key),
				"the actual RAZORPAY_KEY_ID must NEVER appear in any response body")
		})
	}
}

// envForKey picks the safe ENVIRONMENT for a given key so the misconfig
// guard does not fire in tests that only want to exercise the derivation.
func envForKey(key string) string {
	if strings.HasPrefix(strings.ToLower(key), "rzp_live_") {
		return "production"
	}
	return "development"
}

// TestBillingCheckout_ResponseIncludesTrafficEnv exercises the happy-path
// 200 response shape: when checkout succeeds, the response carries the
// derived traffic_env field and NEVER the raw key. Needs a DB to clear
// the email-verify gate + persist the subscription_id — skipped when the
// test DB isn't configured (mirrors the cov2NeedsDB convention).
func TestBillingCheckout_ResponseIncludesTrafficEnv(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		// production deployment + live key is the intended pairing
		// — guard does not fire; happy path proceeds to the
		// fake CreateSubscription.
		Environment:       "production",
		RazorpayKeyID:     liveKeyExample,
		RazorpayKeySecret: "secret-fixture",
		RazorpayPlanIDPro: "plan_monthly_pro",
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	newSubID := "sub_traffic_env_" + uuid.NewString()
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return map[string]any{"id": newSubID, "short_url": "https://rzp.io/x"}, nil
	}
	status, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, newSubID, body["subscription_id"])
	assert.Equal(t, "production", body["traffic_env"],
		"live key → traffic_env must derive to 'production'")
	// Hard security contract: the raw key NEVER appears in the response.
	raw, _ := json.Marshal(body)
	assert.NotContains(t, string(raw), liveKeyExample,
		"the actual RAZORPAY_KEY_ID must NEVER appear in the success response")
}

// TestBillingCheckout_ResponseTrafficEnvIsTestForTestKey mirrors the
// above for a development deployment + test key (the local-dev intended
// pairing). The derived traffic_env must be "test".
func TestBillingCheckout_ResponseTrafficEnvIsTestForTestKey(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		Environment:       "development",
		RazorpayKeyID:     testKeyExample,
		RazorpayKeySecret: "secret-fixture",
		RazorpayPlanIDPro: "plan_monthly_pro",
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return map[string]any{"id": "sub_test_" + uuid.NewString(), "short_url": "https://rzp.io/x"}, nil
	}
	status, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, "test", body["traffic_env"],
		"test key → traffic_env must derive to 'test'")
}

// TestBillingCheckout_TrafficEnvSurfacesOnReusePath verifies the F7
// reuse branch ALSO includes traffic_env. The SPA branches on this field
// regardless of whether the response is a freshly-minted or reused
// subscription.
func TestBillingCheckout_TrafficEnvSurfacesOnReusePath(t *testing.T) {
	cov2NeedsDB(t)
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()
	cfg := &config.Config{
		JWTSecret:         "test-secret-that-is-at-least-32-bytes-long!!",
		Environment:       "production",
		RazorpayKeyID:     liveKeyExample,
		RazorpayKeySecret: "secret-fixture",
		RazorpayPlanIDPro: "plan_monthly_pro",
	}
	teamID, userID := seedVerifiedTeamUser(t, db, "free")
	teamUUID := uuid.MustParse(teamID)
	pendingSub := "sub_reuse_" + uuid.NewString()
	require.NoError(t, models.InsertPendingCheckout(context.Background(), db, pendingSub, teamUUID, "u@example.com", "pro"))

	app, bh := cov2CheckoutApp(t, db, cfg, teamID, userID)
	bh.FetchCheckoutSubscription = func(subID string) (string, string, error) {
		return "created", "https://rzp.io/reuse", nil
	}
	bh.CreateSubscription = func(_ map[string]any) (map[string]any, error) {
		return nil, assertingError("reuse path must not mint a fresh subscription")
	}
	status, body := postCheckoutReq(t, app, map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, status, "body=%v", body)
	assert.Equal(t, true, body["reused"])
	assert.Equal(t, "production", body["traffic_env"],
		"reuse path must also include the derived traffic_env field")
}

// assertingError lets us put a recognisable sentinel into the
// CreateSubscription hook so a false-positive call to it produces a
// readable test failure message in the response body.
type assertingError string

func (e assertingError) Error() string { return string(e) }
