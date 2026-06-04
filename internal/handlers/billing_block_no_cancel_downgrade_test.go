package handlers_test

// billing_block_no_cancel_downgrade_test.go — W3 §E10: there is NO self-serve
// cancel or downgrade path.
//
// Policy (memory: project_no_self_serve_cancel_downgrade): cancellation and
// downgrade are SUPPORT-ONLY. Downgrade flows through the Razorpay
// subscription.cancelled / .updated webhook or a support agent; a paying team
// must NOT be able to drop itself to a cheaper tier or cancel via any
// session-authenticated endpoint. The self-serve POST /billing/cancel was
// REMOVED (router.go documents the removal next to /billing/change-plan).
//
// Two complementary assertions:
//   1. ROUTE NEGATIVE: string-parse the live router.go and prove no route
//      registers a self-serve cancel/downgrade verb. This is the same
//      source-scan technique the OpenAPI route-parity test uses
//      (extractRouterRoutes) so it tracks the real registration table, not a
//      stale mental model. If someone re-adds POST /billing/cancel, this reds.
//   2. HANDLER NEGATIVE: drive the real ChangePlanAPI with a lower-or-equal
//      target tier and assert it is rejected with downgrade_not_self_serve +
//      a mailto:support agent_action — the exact policy in
//      billing.go:ChangePlanAPI. This is verified against the code, not
//      assumed: a downgrade returns 400 downgrade_not_self_serve, NOT a
//      silent tier drop.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
)

// blockRouterRoute is a (method, path, isAdmin) tuple parsed from router.go.
// Local to this W3 file because the OpenAPI test's identically-shaped parser
// lives in the white-box `handlers` test package and is not reachable from
// this black-box `handlers_test` package.
type blockRouterRoute struct {
	method  string
	path    string
	isAdmin bool
}

// blockExtractRouterRoutes string-parses router.go and returns every literal
// route registration. Same conservative technique the OpenAPI route-parity
// test uses: it expects a literal "(" after the verb and a quoted path as the
// first arg, skipping any dynamic registration (router.go uses only literal
// paths today). Groups carry their URL prefix so the returned path is fully
// qualified.
func blockExtractRouterRoutes(src string) []blockRouterRoute {
	patterns := []struct {
		groupRe   *regexp.Regexp
		urlPrefix string
		isAdmin   bool
	}{
		{regexp.MustCompile(`\bapp\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "", false},
		{regexp.MustCompile(`\bapi\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/api/v1", false},
		{regexp.MustCompile(`\badminGroup\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/api/v1/<admin>", true},
		{regexp.MustCompile(`\bdeployGroup\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/deploy", false},
		{regexp.MustCompile(`\binternal\.(Get|Post|Put|Patch|Delete)\("([^"]+)"`), "/internal", false},
	}
	var out []blockRouterRoute
	for _, p := range patterns {
		for _, m := range p.groupRe.FindAllStringSubmatch(src, -1) {
			path := m[2]
			if p.urlPrefix != "" {
				if !strings.HasPrefix(path, "/") {
					path = "/" + path
				}
				path = p.urlPrefix + path
			}
			out = append(out, blockRouterRoute{method: strings.ToUpper(m[1]), path: path, isAdmin: p.isAdmin})
		}
	}
	return out
}

// forbiddenSelfServeBillingPaths is the set of route SUFFIXES that, if they
// ever appear as a registered self-serve (session-authenticated, non-admin,
// non-webhook) route, would constitute a self-serve cancel/downgrade surface
// the policy forbids. Matched as a suffix against the parsed router path so
// both the legacy alias and the /api/v1 group form are caught.
var forbiddenSelfServeBillingPaths = []string{
	"/billing/cancel",
	"/billing/downgrade",
	"/billing/subscription/cancel",
	"/subscription/cancel",
}

// TestBillingBlock_NoSelfServeCancelOrDowngradeRoute parses router.go and
// asserts none of the forbidden self-serve cancel/downgrade paths are
// registered on a non-admin route. Admin routes (e.g. an operator demote) are
// allowed and excluded — cancellation IS supported, just support/operator-side.
//
// This does not require a DB — it reads the router source, the same way
// TestOpenAPI route-parity does, so it runs even in the -short unit lane.
func TestBillingBlock_NoSelfServeCancelOrDowngradeRoute(t *testing.T) {
	routerPath := filepath.Join("..", "router", "router.go")
	src, err := os.ReadFile(routerPath)
	require.NoError(t, err, "read router.go")

	routes := blockExtractRouterRoutes(string(src))
	require.NotEmpty(t, routes,
		"blockExtractRouterRoutes returned 0 — parser is out of sync with router.go (the negative assertion would pass vacuously)")

	// Guard against a vacuous pass: confirm the parser actually sees the
	// billing block by requiring the legitimate change-plan route to be
	// present. If the parser silently broke, this trips before the negative
	// assertion can give a false green.
	var sawChangePlan bool
	for _, r := range routes {
		if strings.HasSuffix(r.path, "/billing/change-plan") {
			sawChangePlan = true
			break
		}
	}
	require.True(t, sawChangePlan,
		"expected the router parser to see POST /billing/change-plan — if it doesn't, the no-cancel negative assertion is meaningless")

	for _, r := range routes {
		if r.isAdmin {
			continue // operator/support-side cancellation is allowed.
		}
		for _, forbidden := range forbiddenSelfServeBillingPaths {
			assert.Falsef(t, strings.HasSuffix(r.path, forbidden),
				"self-serve cancel/downgrade is support-only (§E10, memory project_no_self_serve_cancel_downgrade) — "+
					"router.go must not register a non-admin route ending in %q, but found %s %s",
				forbidden, r.method, r.path)
		}
	}
}

// TestBillingBlock_ChangePlanRejectsDowngrade pins the handler-level policy: a
// paying team requesting a LOWER or EQUAL tier via the in-app change-plan path
// is rejected with downgrade_not_self_serve and routed to support, NOT
// silently dropped. Verified against billing.go:ChangePlanAPI (it returns 400
// downgrade_not_self_serve + a mailto:support@instanode.dev agent_action for
// any target whose rank ≤ the current tier's rank).
func TestBillingBlock_ChangePlanRejectsDowngrade(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}

	cases := []struct {
		name      string
		startTier string
		target    string
	}{
		{"pro → hobby is a downgrade", "pro", "hobby"},
		{"pro → hobby_plus is a downgrade", "pro", "hobby_plus"},
		{"hobby_plus → hobby is a downgrade", "hobby_plus", "hobby"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, clean := billingBlockDB(t)
			defer clean()
			teamID := mustSeedTeam(t, db, tc.startTier)
			cfg := &config.Config{
				JWTSecret:               billingBlockJWTSecret,
				RazorpayKeyID:           "rzp_test_k",
				RazorpayKeySecret:       "s",
				RazorpayPlanIDHobby:     "plan_hobby",
				RazorpayPlanIDHobbyPlus: "plan_hobby_plus",
				RazorpayPlanIDPro:       "plan_pro",
			}
			app := changePlanAppReal(t, db, cfg, teamID)
			code, body := changePlanReq(t, app, map[string]any{"target_plan": tc.target})

			assert.Equal(t, http.StatusBadRequest, code, "downgrade must be a 400, body=%v", body)
			assert.Equal(t, "downgrade_not_self_serve", body["error"],
				"%s must be rejected as a support-only downgrade, not applied", tc.name)
			// The agent_action must route the user to support so an agent does
			// not retry or invent a different path.
			action, _ := body["agent_action"].(string)
			assert.Contains(t, strings.ToLower(action), "support",
				"downgrade rejection must carry a support-routing agent_action (got %q)", action)

			// And CRITICALLY: the team's tier must be UNCHANGED — a downgrade
			// rejection that still mutated the row would be the worst outcome.
			assert.Equal(t, tc.startTier, billingBlockTeamTier(t, db, teamID),
				"a rejected downgrade must not mutate the team's plan_tier")
		})
	}
}

// TestBillingBlock_ChangePlanSamePlanRejected covers the lateral/no-op edge:
// requesting the tier the team already holds is rejected with same_plan (not
// treated as a downgrade, not a no-op success that churns the Razorpay
// subscription). Part of the §E10 surface — no self-serve tier mutation that
// isn't a genuine upgrade.
func TestBillingBlock_ChangePlanSamePlanRejected(t *testing.T) {
	if billingBlockSkipNoDB(t) {
		return
	}
	db, clean := billingBlockDB(t)
	defer clean()
	teamID := mustSeedTeam(t, db, "pro")
	cfg := &config.Config{
		JWTSecret:         billingBlockJWTSecret,
		RazorpayKeyID:     "rzp_test_k",
		RazorpayKeySecret: "s",
		RazorpayPlanIDPro: "plan_pro",
	}
	app := changePlanAppReal(t, db, cfg, teamID)
	code, body := changePlanReq(t, app, map[string]any{"target_plan": "pro"})
	assert.Equal(t, http.StatusBadRequest, code, "body=%v", body)
	assert.Equal(t, "same_plan", body["error"],
		"requesting the current tier must return same_plan, not a no-op success")
	assert.Equal(t, "pro", billingBlockTeamTier(t, db, teamID))
}
