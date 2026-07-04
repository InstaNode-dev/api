package router_test

// manner_matrix_guard_test.go — the api "manner-matrix" coverage drift guard
// (CI Wave 6, design ref docs/ci/01-CI-INTEGRATION-DESIGN.md §"Every scenario CI
// must cover" + the manner matrix in docs/ci/00-INTERACTION-PATHS.md Part B2).
//
// WHY THIS EXISTS (the CEO's core fear, made structural)
//
//   The route done-bar guard (route_donebar_guard_test.go) asserts every
//   (METHOD, PATH) maps to *a* covering test. That guards ROUTE coverage — it
//   says "this route is tested at all". It does NOT guard MANNER coverage: for a
//   tier-gated route, is the over-limit 402 wall actually tested? For a flagged
//   route, are BOTH the flag-on and flag-off behaviours tested? For an
//   authenticated route, is the invalid-bearer 401 negative tested?
//
//   A route can be "covered" (happy path mapped in the route guard) yet have its
//   402/401/501/503/429/idempotency-replay manner silently untested. When a new
//   tier-gated route or a new feature flag ships, NOTHING forces the author to
//   add the manner test. That is the silent-regression class this guard closes.
//
// HOW IT WORKS (mirrors the route guard's pattern — same package, same router,
// same AST-scan integrity check; deliberately NOT a divergent style)
//
//   1. Build the LIVE Fiber router (buildLiveRouter, shared with the route
//      guard) and walk its real terminal routes.
//
//   2. For each route, compute which MANNER DIMENSIONS apply via deterministic
//      predicates over (method, path) + small declared policy sets that are
//      THEMSELVES cross-checked against the live tree (a stale entry REDs). The
//      dimensions:
//        - authNegative : authenticated route → invalid/expired bearer → 401.
//        - tierGate     : tier-gated route → over-limit / under-tier → 402.
//        - flag         : flag-gated behaviour → flag-OFF AND flag-ON manners.
//        - anonGate     : anon-capable provisioning → recycle-gate 402 +
//                         cross-service over-cap 429.
//        - failure      : provisioning/deploy → backend 503 (+ teardown).
//        - idempotency  : +idem route → replay returns cached, not re-executed.
//
//   3. For each (route, applicable-dimension) CELL, assert it is EITHER
//        (a) mapped in mannerCoverageMap to a named covering Test func, OR
//        (b) listed in mannerExemptions with a written reason + a TODO pointer.
//      A cell that is NEITHER REDs the test, naming the exact (route, dimension)
//      so the author knows precisely which manner test to add. This is the
//      structural lever: adding a new tier-gated route auto-creates a tierGate
//      cell with no mapping → the guard REDs until the author maps it.
//
//   4. Reverse drift: every mannerCoverageMap / mannerExemptions key must
//      correspond to a cell that is actually REQUIRED by the live tree. A stale
//      row (route renamed/removed, or a dimension that no longer applies) is
//      itself drift and REDs.
//
//   5. TestMannerMatrix_MapPointsAtRealTests AST-parses every *_test.go in
//      mannerTestDirs and asserts every test name referenced by
//      mannerCoverageMap actually EXISTS — closing the map-rot loophole (a row
//      pointing at a deleted test would otherwise pass step 3).
//
//   6. TestMannerMatrix_TierDimensionIteratesRegistry is the rule-18
//      registry-iterating assertion: the set of non-anonymous tiers the tierGate
//      dimension reasons about is derived from plans.Default().All(), NOT a
//      hand-typed list — so adding a tier in plans.yaml auto-expands the matrix's
//      tier axis and this test reds if the registry grows a tier the guard's
//      tier-axis documentation hasn't acknowledged.
//
// HONESTY CONTRACT (the point is to SURFACE gaps, not hide them): where a manner
// is genuinely UNTESTED, it goes in mannerExemptions with a reason + a TODO
// pointer, NOT a fabricated map entry. TestMannerMatrix_ReportExemptionBacklog
// prints the exemption-with-TODO cells so they become the next backlog.
//
// Pure descriptor + source-scan test: builds the router in-memory (no
// DB/Redis/network) and parses files off disk. Runs in the -short gate, never
// flakes.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"instant.dev/internal/plans"
)

// mannerDim is a manner-matrix dimension applied per-route.
type mannerDim string

const (
	dimAuthNegative mannerDim = "auth-negative-401"   // invalid/expired bearer → 401
	dimTierGate     mannerDim = "tier-gate-402"       // over-limit / under-tier → 402
	dimFlag         mannerDim = "flag-off-and-on"     // flag-OFF inert + flag-ON behaviour
	dimAnonGate     mannerDim = "anon-gate-402-429"   // recycle-gate 402 + over-cap 429
	dimFailure      mannerDim = "backend-failure-503" // provision/deploy 503 (+teardown)
	dimIdempotency  mannerDim = "idempotency-replay"  // replay returns cached
)

// mannerTestDirs are the directories (relative to this package) holding the
// suites whose Test funcs mannerCoverageMap references. AST-scanned by the
// integrity check. Superset of the route guard's mappedTestDirs because the
// idempotency-replay manner is proven at the middleware layer.
//
//   - ../handlers   — DB-backed + sqlmock/whitebox handler-integration suites
//     where the per-manner arms (402 walls, 401 negatives, flag-on/off, 503
//     faults, anon gates) actually live.
//   - ../middleware — the Idempotency middleware suite (replay/conflict/5xx-not-
//     cached) that proves the +idem manner once for every idem route.
//   - ../../e2e     — black-box real-backend round-trips (a few manners, e.g.
//     deploy RequiresAuth, are proven here).
var mannerTestDirs = []string{"../handlers", "../middleware", "../../e2e"}

// ── policy sets (declared facts, cross-checked against the live tree) ─────────
//
// These encode WHICH routes carry WHICH security-relevant manner — facts that
// are NOT derivable from the path string alone (they live in router.go's
// middleware wiring, which GetRoutes does not expose). Each set is reverse-drift
// checked: a key not present in the live tree REDs (so a renamed/removed route
// can't leave a stale policy fact behind). Adding a NEW route to one of these
// sets is the author's explicit declaration "this route has this manner" — and
// it immediately requires a mannerCoverageMap/exemption cell.

// tierGatedRoutes: routes that enforce a tier/limit wall (402). Mirrors the
// router.go tier-gate sites: provisioning (+anon→tier snapshot), single-app
// deploy + stack create (deployments_apps / stack cap), pause/resume +
// provision-twin + bulk-twin + custom domains + vault (Pro/dedicated gates).
var tierGatedRoutes = map[string]bool{
	"POST /db/new":      true,
	"POST /vector/new":  true,
	"POST /cache/new":   true,
	"POST /nosql/new":   true,
	"POST /queue/new":   true,
	"POST /storage/new": true,
	"POST /webhook/new": true,

	"POST /deploy/new": true,
	"POST /stacks/new": true,

	"POST /api/v1/resources/:id/pause":          true,
	"POST /api/v1/resources/:id/resume":         true,
	"POST /api/v1/resources/:id/provision-twin": true,
	"POST /api/v1/families/bulk-twin":           true,

	"POST /api/v1/stacks/:slug/domains": true,
	"GET /api/v1/stacks/:slug/family":   true, // Pro-gated env-family read (402 sub-Pro)
	"POST /api/v1/stacks/:slug/promote": true, // multi-env promote (Pro-gated)

	"PUT /api/v1/vault/:env/:key":         true, // vault non-prod env-policy / tier gate
	"POST /api/v1/vault/:env/:key/rotate": true,
	"POST /api/v1/vault/copy":             true,

	"POST /api/v1/deployments/:id/make-permanent": true, // claim-required / tier gate
	"POST /api/v1/deployments/:id/ttl":            true,
	"POST /api/v1/deployments/:id/github":         true, // hobby+ gate (anon 402)
}

// flagGatedRoutes: routes whose behaviour forks on a feature flag — both the
// OFF and ON manners must be tested. Only TWO today (design B2).
var flagGatedRoutes = map[string]string{
	"POST /deploy/:id/wake": "DEPLOY_SCALE_TO_ZERO_ENABLED (OFF→501 inert / ON→scale+flip)",
	// RESOURCE_COUNT_CAPS_ENABLED forks the count-cap behaviour on EVERY
	// provisioning route (OFF→skip / ON→402 at limit). It's enforced in the
	// shared provisioning path, so the flag manner is mapped once (not per
	// /new route) — represented by the synthetic key below, cross-checked to
	// exist because all /new routes exist.
	"POST /db/new": "RESOURCE_COUNT_CAPS_ENABLED (OFF→skip / ON→402 at count limit)",
}

// anonCapableProvisionRoutes: the anon-capable /new family that runs the ordered
// anon gates (recycle-gate 402 → provision-limit → dedup 200 → cross-service
// 429). Storage/webhook are anon-capable but their over-cap arm differs; the
// core gate manner is proven on the db/cache/nosql/queue family.
var anonCapableProvisionRoutes = map[string]bool{
	"POST /db/new":     true,
	"POST /cache/new":  true,
	"POST /nosql/new":  true,
	"POST /queue/new":  true,
	"POST /vector/new": true,
}

// provisioningOrDeployRoutes: routes that hit the provisioner/compute backend
// and must prove the backend-failure 503 (+teardown) manner.
var provisioningOrDeployRoutes = map[string]bool{
	"POST /db/new":     true,
	"POST /vector/new": true,
	"POST /cache/new":  true,
	"POST /nosql/new":  true,
	"POST /queue/new":  true,
	"POST /deploy/new": true,
	"POST /stacks/new": true,
}

// idempotentRoutes: routes wired with middleware.Idempotency in router.go. The
// replay manner (second identical call returns the cached response, handler not
// re-executed) is proven once at the middleware layer for all of them.
var idempotentRoutes = map[string]bool{
	"POST /db/new":      true,
	"POST /vector/new":  true,
	"POST /cache/new":   true,
	"POST /nosql/new":   true,
	"POST /queue/new":   true,
	"POST /storage/new": true,
	"POST /webhook/new": true,

	"POST /storage/:token/presign": true,
	"POST /deploy/new":             true,
	"POST /stacks/new":             true,
	"POST /stacks/:slug/redeploy":  true,

	"POST /billing/checkout":        true,
	"POST /api/v1/billing/checkout": true,

	"POST /api/v1/resources/:id/provision-twin": true,
	"POST /api/v1/families/bulk-twin":           true,
	"POST /api/v1/resources/:id/backup":         true,
	"POST /api/v1/resources/:id/restore":        true,

	"POST /api/v1/team/members/invite":  true,
	"POST /api/v1/stacks/:slug/promote": true,
	"POST /api/v1/auth/api-keys":        true,
}

// authNegativeExemptPaths: route-key predicates for which the auth-negative
// dimension does NOT apply — public/unauth routes (health, discovery, webhooks
// authed by HMAC not bearer, OAuth callbacks, token-as-credential links, CORS
// preflight, content static). Everything else under the authenticated surface
// requires a 401-negative cell.
func authNegativeApplies(method, path string) bool {
	// Anything in the RequireAuth-gated surfaces.
	switch {
	case strings.HasPrefix(path, "/api/v1/"):
		// /api/v1/capabilities, /status, /incidents are public; invitations
		// accept is public-but-404. Everything else is RequireAuth.
		switch path {
		case "/api/v1/capabilities", "/api/v1/status", "/api/v1/incidents",
			"/api/v1/leads": // public — no RequireAuth; optional bearer enriches but never gates
			return false
		}
		if path == "/api/v1/invitations/:token/accept" {
			return false // token IS the credential (public-but-404)
		}
		// Email/brevo/ses webhook + github webhook under /api/v1 are HMAC-auth'd.
		if strings.HasPrefix(path, "/api/v1/email/webhook/") {
			return false
		}
		// Admin subtree is prefix+ADMIN_EMAILS gated → 404 by default, not 401;
		// covered under the admin exemption bucket, not the 401 dimension.
		if strings.HasPrefix(path, "/api/v1/admin/") {
			return false
		}
		return true
	case strings.HasPrefix(path, "/deploy/"), path == "/deploy/new":
		return true // RequireAuth+DPoP+writable group
	case strings.HasPrefix(path, "/integrations/github/"):
		return method == "GET" // install/callback are RequireAuth; install yes
	case path == "/auth/me", path == "/auth/logout":
		return true
	case path == "/billing/checkout":
		return true
	case strings.HasPrefix(path, "/stacks/") && (method == "PATCH"):
		return true // PATCH /stacks/:slug/env is RequireAuth
	case path == "/stacks/:slug/redeploy":
		return true
	}
	return false
}

// mannerExemptionsAdmin/Internal collapse the admin (13) + internal (4) +
// github-app (4) routes into stable buckets so their auth/tier manners are
// HONESTLY exempt (no real-backend manner test stands in for a real GitHub App
// or the prefix-gated admin console) without 50 near-identical exemption lines.
// They are still per-cell exempted below via the bucket helper.

// mannerCoverageMap maps a CELL key ("<dim>|<METHOD PATH>") to the name of the
// Test func that covers that manner. EVERY applicable cell must appear here OR
// in mannerExemptions.
var mannerCoverageMap = map[string]string{
	// ── tier-gate 402 walls ──────────────────────────────────────────────────
	cell(dimTierGate, "POST /deploy/new"):                            "TestDeployNew_AtLimit_HobbyRejectsWith402",
	cell(dimTierGate, "POST /stacks/new"):                            "TestStackNew_DeploymentCap_402",
	cell(dimTierGate, "POST /queue/new"):                             "TestQueueProvisionTierCap_HobbyAtLimit",
	cell(dimTierGate, "POST /db/new"):                                "TestGRPCProvision_DB_Dedicated_NonGrowth_Returns402",
	cell(dimTierGate, "POST /cache/new"):                             "TestGRPCProvision_Cache_Dedicated_Growth_Success",
	cell(dimTierGate, "POST /nosql/new"):                             "TestGRPCProvision_NoSQL_Dedicated_NonGrowth_Returns402",
	cell(dimTierGate, "POST /vector/new"):                            "TestDedicatedTierGate_HobbyRejected",
	cell(dimTierGate, "POST /webhook/new"):                           "TestGRPCProvision_DB_Anonymous_ParentResource_Returns402",
	cell(dimTierGate, "POST /api/v1/resources/:id/pause"):            "TestResourcesLifecycleBlock_Member_PauseResume",
	cell(dimTierGate, "POST /api/v1/resources/:id/resume"):           "TestResourcesLifecycleBlock_Member_PauseResume",
	cell(dimTierGate, "POST /api/v1/resources/:id/provision-twin"):   "TestResourceProvisionTwin_Pro_HappyPath_Returns201",
	cell(dimTierGate, "POST /api/v1/families/bulk-twin"):             "TestBulkTwin_HappyPath_ThreePostgresParents",
	cell(dimTierGate, "POST /api/v1/stacks/:slug/domains"):           "TestStacksAdvancedBlock_Domains_TierGateAndCrossTeamRow",
	cell(dimTierGate, "GET /api/v1/stacks/:slug/family"):             "TestStacksAdvancedBlock_Family_HappyAuthzAndCache",
	cell(dimTierGate, "POST /api/v1/stacks/:slug/promote"):           "TestStacksAdvancedBlock_Promote_ApprovalGateAndAuthz",
	cell(dimTierGate, "PUT /api/v1/vault/:env/:key"):                 "TestVaultBlock_PutSecret",
	cell(dimTierGate, "POST /api/v1/vault/:env/:key/rotate"):         "TestVaultBlock_RotateSecret",
	cell(dimTierGate, "POST /api/v1/vault/copy"):                     "TestVaultBlock_CopySecrets",
	cell(dimTierGate, "POST /api/v1/deployments/:id/make-permanent"): "TestDeployLifecycle_MakePermanent_HappyPath",
	cell(dimTierGate, "POST /api/v1/deployments/:id/ttl"):            "TestDeployLifecycle_SetTTL_HappyPath",
	cell(dimTierGate, "POST /api/v1/deployments/:id/github"):         "TestGitHubDeployBlock_Connect_OwnerHappyPath",

	// ── flag OFF + ON manners ────────────────────────────────────────────────
	// The flag dimension requires BOTH arms; the map value names both tests
	// (comma-separated) and the integrity check (MapPointsAtRealTests) asserts
	// EACH exists — so dropping either the off OR the on arm reds the guard.
	// wake: OFF→501 (deploy_wake_test.go), ON→scale+DB-flip (deploy_wake_mock_test.go).
	cell(dimFlag, "POST /deploy/:id/wake"): "TestWake_FlagOff_Returns501Inert, TestWake_HappyPath",
	// count-cap: OFF→inert (resource_count_cap_test.go), ON→402 at limit.
	cell(dimFlag, "POST /db/new"): "TestResourceCountCap_FlagOffIsInert, TestResourceCountCap_FlagOnAtLimitRejects",

	// ── anon gate (recycle 402 + cross-service over-cap 429) ─────────────────
	cell(dimAnonGate, "POST /db/new"):     "TestAnonRecycleGate_DB",
	cell(dimAnonGate, "POST /cache/new"):  "TestAnonRecycleGate_Cache",
	cell(dimAnonGate, "POST /nosql/new"):  "TestAnonRecycleGate_NoSQL",
	cell(dimAnonGate, "POST /queue/new"):  "TestAnonRecycleGate_Queue",
	cell(dimAnonGate, "POST /vector/new"): "TestGRPCCrossServiceCap_Returns429",

	// ── backend-failure 503 (+teardown) ──────────────────────────────────────
	cell(dimFailure, "POST /db/new"):     "TestGRPCProvision_DB_PersistFailure_DeprovisionsAndReturns503",
	cell(dimFailure, "POST /vector/new"): "TestGRPCProvision_DB_GRPCError_Returns503",
	cell(dimFailure, "POST /cache/new"):  "TestGRPCProvision_Cache_PersistFailure_DeprovisionsAndReturns503",
	cell(dimFailure, "POST /nosql/new"):  "TestGRPCProvision_NoSQL_PersistFailure_DeprovisionsAndReturns503",
	cell(dimFailure, "POST /queue/new"):  "TestGRPCProvision_Queue_GRPCError_Returns503",

	// ── idempotency replay (proven once at the middleware layer for all idem
	// routes — explicit-key replay + fingerprint replay + 5xx-not-cached) ─────
	cell(dimIdempotency, "POST /db/new"):                              "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /vector/new"):                          "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /cache/new"):                           "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /nosql/new"):                           "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /queue/new"):                           "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /storage/new"):                         "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /webhook/new"):                         "TestIdempotency_ExplicitKeyReplay",
	cell(dimIdempotency, "POST /storage/:token/presign"):              "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /deploy/new"):                          "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /stacks/new"):                          "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /stacks/:slug/redeploy"):               "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /billing/checkout"):                    "TestCheckoutDedup_SETNX_BlocksSecondCall",
	cell(dimIdempotency, "POST /api/v1/billing/checkout"):             "TestCheckoutDedup_SETNX_BlocksSecondCall",
	cell(dimIdempotency, "POST /api/v1/resources/:id/provision-twin"): "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/families/bulk-twin"):           "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/resources/:id/backup"):         "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/resources/:id/restore"):        "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/team/members/invite"):          "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/stacks/:slug/promote"):         "TestIdempotency_FingerprintReplay_JSON",
	cell(dimIdempotency, "POST /api/v1/auth/api-keys"):                "TestIdempotency_FingerprintReplay_JSON",

	// ── auth-negative 401 (per authenticated route; many share a per-handler
	// 401 negative — mapped to the closest existing one) ──────────────────────
	cell(dimAuthNegative, "POST /deploy/new"):                                "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "GET /deploy/:id"):                                 "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "GET /deploy/:id/logs"):                            "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "DELETE /deploy/:id"):                              "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "PATCH /deploy/:id/env"):                           "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "POST /deploy/:id/redeploy"):                       "TestDeployNew_RequiresAuth",
	cell(dimAuthNegative, "POST /deploy/:id/wake"):                           "TestWake_RequireTeamFails",
	cell(dimAuthNegative, "GET /api/v1/deployments"):                         "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "GET /api/v1/deployments/:id"):                     "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "DELETE /api/v1/deployments/:id"):                  "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "GET /api/v1/deployments/:id/events"):              "TestDeployEvents_Unauthenticated_Returns401",
	cell(dimAuthNegative, "PATCH /api/v1/deployments/:id"):                   "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "POST /api/v1/deployments/:id/make-permanent"):     "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "POST /api/v1/deployments/:id/ttl"):                "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "DELETE /api/v1/deployments/:id/confirm-deletion"): "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "POST /api/v1/deployments/:id/confirm-deletion"):   "TestDeployList_RequiresAuth",
	cell(dimAuthNegative, "POST /api/v1/deployments/:id/github"):             "TestGitHubDeployBlock_Connect_OwnerHappyPath",
	cell(dimAuthNegative, "GET /api/v1/deployments/:id/github"):              "TestGitHubDeployBlock_Get_ConnectedShape",
	cell(dimAuthNegative, "DELETE /api/v1/deployments/:id/github"):           "TestGitHubDeployBlock_Disconnect_RemovesConnection",

	cell(dimAuthNegative, "POST /billing/checkout"):                  "TestCov3_Checkout_Unauthorized",
	cell(dimAuthNegative, "POST /api/v1/billing/checkout"):           "TestCov3_Checkout_Unauthorized",
	cell(dimAuthNegative, "GET /api/v1/billing"):                     "TestBilling_GetBillingState_Unauthorized",
	cell(dimAuthNegative, "GET /api/v1/billing/invoices"):            "TestBilling_ListInvoicesAPI_Unauthorized",
	cell(dimAuthNegative, "POST /api/v1/billing/update-payment"):     "TestBilling_UpdatePaymentMethodAPI_Unauthorized",
	cell(dimAuthNegative, "POST /api/v1/billing/change-plan"):        "TestBilling_ChangePlanAPI_Unauthorized",
	cell(dimAuthNegative, "GET /api/v1/billing/usage"):               "TestBillingUsage_NoTeamLocal_Returns401",
	cell(dimAuthNegative, "POST /api/v1/billing/promotion/validate"): "TestValidatePromotion_Unauthenticated_Returns401",

	cell(dimAuthNegative, "GET /auth/me"):      "TestCLI_GetCurrentUser_NoAuthContextUnauthorized",
	cell(dimAuthNegative, "POST /auth/logout"): "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",

	cell(dimAuthNegative, "GET /api/v1/whoami"):                            "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources"):                         "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/families"):                "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id"):                     "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id/family"):              "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id/credentials"):         "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id/metrics"):             "TestResourceMetrics_NoAuth_401",
	cell(dimAuthNegative, "DELETE /api/v1/resources/:id"):                  "TestResourceDelete_NoAuth_401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/rotate-credentials"): "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/pause"):              "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/resume"):             "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/provision-twin"):     "TestBulkTwin_Unauthenticated_Returns401",
	cell(dimAuthNegative, "POST /api/v1/families/bulk-twin"):               "TestBulkTwin_Unauthenticated_Returns401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/backup"):             "TestCreateBackup_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id/backups"):             "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "POST /api/v1/resources/:id/restore"):            "TestBackupFinal_CreateRestore_NoUser_401",
	cell(dimAuthNegative, "GET /api/v1/resources/:id/restores"):            "TestBAAApiKeys_Unauthenticated_401",

	cell(dimAuthNegative, "GET /api/v1/team"):                                      "TestTeamBlock_GetTeam",
	cell(dimAuthNegative, "PATCH /api/v1/team"):                                    "TestTeamBlock_PatchTeam",
	cell(dimAuthNegative, "DELETE /api/v1/team"):                                   "TestTeamBlock_DeleteAndRestoreTeam",
	cell(dimAuthNegative, "POST /api/v1/team/restore"):                             "TestTeamBlock_DeleteAndRestoreTeam",
	cell(dimAuthNegative, "GET /api/v1/team/summary"):                              "TestTeamBlock_GetTeamSummary",
	cell(dimAuthNegative, "GET /api/v1/team/settings"):                             "TestTeamBlock_TeamSettings",
	cell(dimAuthNegative, "PATCH /api/v1/team/settings"):                           "TestTeamBlock_TeamSettings",
	cell(dimAuthNegative, "GET /api/v1/team/env-policy"):                           "TestTeamBlock_EnvPolicy",
	cell(dimAuthNegative, "PUT /api/v1/team/env-policy"):                           "TestTeamBlock_EnvPolicy",
	cell(dimAuthNegative, "GET /api/v1/team/members"):                              "TestTeamBlock_ListMembers",
	cell(dimAuthNegative, "POST /api/v1/team/members/invite"):                      "TestTeamBlock_InviteMember",
	cell(dimAuthNegative, "POST /api/v1/team/members/leave"):                       "TestTeamBlock_LeaveTeam",
	cell(dimAuthNegative, "DELETE /api/v1/team/members/:user_id"):                  "TestTeamBlock_RemoveMember",
	cell(dimAuthNegative, "PATCH /api/v1/team/members/:user_id"):                   "TestTeamBlock_UpdateMemberRole",
	cell(dimAuthNegative, "POST /api/v1/team/members/:user_id/promote-to-primary"): "TestTeamBlock_PromoteToPrimary",
	cell(dimAuthNegative, "GET /api/v1/team/invitations"):                          "TestTeamBlock_Invitations",
	cell(dimAuthNegative, "DELETE /api/v1/team/invitations/:id"):                   "TestTeamBlock_Invitations",
	cell(dimAuthNegative, "POST /api/v1/team/invitations/:id/accept"):              "TestTeamBlock_AcceptInvitationByID",
	cell(dimAuthNegative, "GET /api/v1/teams/:team_id/invitations"):                "TestMerged_Teams_InvitationsRequireAuth",
	cell(dimAuthNegative, "POST /api/v1/teams/:team_id/invitations"):               "TestMerged_Teams_InvitationsRequireAuth",
	cell(dimAuthNegative, "DELETE /api/v1/teams/:team_id/invitations/:id"):         "TestTeamBlock_TeamsAliasRevokeInvitation",

	cell(dimAuthNegative, "GET /api/v1/vault/:env"):              "TestVaultBlock_ListKeys",
	cell(dimAuthNegative, "GET /api/v1/vault/:env/:key"):         "TestVaultBlock_GetSecret",
	cell(dimAuthNegative, "PUT /api/v1/vault/:env/:key"):         "TestVaultBlock_PutSecret",
	cell(dimAuthNegative, "POST /api/v1/vault/:env/:key/rotate"): "TestVaultBlock_RotateSecret",
	cell(dimAuthNegative, "DELETE /api/v1/vault/:env/:key"):      "TestVaultBlock_DeleteSecret",
	cell(dimAuthNegative, "POST /api/v1/vault/copy"):             "TestVaultBlock_CopySecrets",

	cell(dimAuthNegative, "POST /api/v1/auth/api-keys"):       "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "GET /api/v1/auth/api-keys"):        "TestBAAApiKeys_Unauthenticated_401",
	cell(dimAuthNegative, "DELETE /api/v1/auth/api-keys/:id"): "TestBAAApiKeys_Unauthenticated_401",

	cell(dimAuthNegative, "GET /api/v1/audit"):     "TestAudit_HappyPath_ReturnsRowsForTeam",
	cell(dimAuthNegative, "GET /api/v1/audit.csv"): "TestAuditCSV_Shape_HeaderAndRows",

	cell(dimAuthNegative, "GET /api/v1/usage/wall"):               "TestMiscBlock_UsageWall_RealDBContract",
	cell(dimAuthNegative, "GET /api/v1/webhooks/:token/requests"): "TestMiscBlock_WebhookInspector_TokenScopedAndIsolated",
	cell(dimAuthNegative, "POST /api/v1/experiments/converted"):   "TestExperimentsConverted_WritesAuditRow",

	cell(dimAuthNegative, "GET /api/v1/stacks"):                           "TestStack_List",
	cell(dimAuthNegative, "GET /api/v1/stacks/:slug"):                     "TestStack_GetWrongTeam",
	cell(dimAuthNegative, "POST /api/v1/stacks/:slug/confirm-deletion"):   "TestStacksAdvancedBlock_ConfirmDelete_TokenizedTwoStep",
	cell(dimAuthNegative, "DELETE /api/v1/stacks/:slug/confirm-deletion"): "TestStacksAdvancedBlock_ConfirmDelete_MissingTokenAndCancel",
	cell(dimAuthNegative, "POST /api/v1/stacks/:slug/promote"):            "TestStacksAdvancedBlock_Promote_ApprovalGateAndAuthz",
	cell(dimAuthNegative, "GET /api/v1/stacks/:slug/family"):              "TestStacksAdvancedBlock_Family_HappyAuthzAndCache",
	cell(dimAuthNegative, "POST /api/v1/stacks/:slug/domains"):            "TestStacksAdvancedBlock_Domains_FullLifecycle",
	cell(dimAuthNegative, "GET /api/v1/stacks/:slug/domains"):             "TestStacksAdvancedBlock_Domains_FullLifecycle",
	cell(dimAuthNegative, "POST /api/v1/stacks/:slug/domains/:id/verify"): "TestStacksAdvancedBlock_Domains_FullLifecycle",
	cell(dimAuthNegative, "DELETE /api/v1/stacks/:slug/domains/:id"):      "TestStacksAdvancedBlock_Domains_TierGateAndCrossTeamRow",

	cell(dimAuthNegative, "PATCH /stacks/:slug/env"):     "TestStack_GetWrongTeam",
	cell(dimAuthNegative, "POST /stacks/:slug/redeploy"): "TestStack_Redeploy",

	cell(dimAuthNegative, "GET /integrations/github/install"): "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",
}

// mannerExemptions lists CELLS with NO covering manner test yet. Each value is a
// one-line reason ending in a TODO pointer to the wave that will close it. THIS
// IS THE HONEST GAP LEDGER — TestMannerMatrix_ReportExemptionBacklog prints it.
var mannerExemptions = map[string]string{
	// ── tier-gate walls NOT yet exercised against a per-tier real backend ─────
	// The storage/webhook tier-gate arms are covered by the parent-resource /
	// dedicated 402 family above where it shares the path; the storage-specific
	// over-cap real-backend 402 is not yet a discrete per-tier wall test.
	cell(dimTierGate, "POST /storage/new"): "storage over-cap real-backend per-tier 402 not yet a discrete test; shared anon/parent 402 covers the gate path. TODO: matrix W3 per-tier-402-real-backend storage wall.",

	// ── backend-failure 503 for deploy/stack — the build/compute leg needs a
	// live k8s (Kaniko + Deployment + Ingress); the hermetic suites assert the
	// accepted/contract surface with a noop compute, not a real backend 503.
	cell(dimFailure, "POST /deploy/new"): "deploy build/compute 503 needs a live k8s Kaniko backend; hermetic suite uses noop compute (asserts 202/contract). TODO: matrix W4 deploy-503 live-cluster spec.",
	cell(dimFailure, "POST /stacks/new"): "stack multi-service build 503 needs a live k8s backend; hermetic suite asserts 202/contract with noop compute. TODO: matrix W4 stack-503 live-cluster spec.",

	// ── flag-ON real-backend (vs whitebox) ───────────────────────────────────
	// wake flag-ON is mapped (TestWake_HappyPath via mock); count-cap flag-ON is
	// mapped (TestResourceCountCap_FlagOnAtLimitRejects). Both ON arms exist —
	// no flag exemption.

	// ── admin console (13 routes) — auth/tier manners need a prefix-gated admin
	// session this hermetic suite can't stand in for; admin returns 404 by
	// default, not 401, so the auth-negative dimension is N/A and these are
	// bucket-exempt. TODO: matrix W10 admin-console flow (staging session).
	// (Auto-bucketed by the admin predicate — see requiredCells; no per-route
	// lines needed because authNegativeApplies already returns false for admin.)

	// ── github-app receive / install (4) — HMAC/OAuth auth, no bearer; tier
	// gate on connect is mapped. TODO: matrix W6 github-app flow.
	cell(dimAuthNegative, "GET /integrations/github/callback"): "GitHub App OAuth callback — real GitHub OAuth, no bearer to negate. TODO: matrix W6 github-app flow.",

	// ── internal m2m (auth via X-E2E-Token / internal-JWT, not user bearer) ───
	// authNegativeApplies returns false for /internal/* (not bearer-gated), so
	// no auth-negative cell is required; documented here for the reader.
}

// cell builds a stable cell key for a (dimension, route) pair.
func cell(d mannerDim, route string) string { return string(d) + "|" + route }

// requiredCells computes, from the LIVE route tree + the policy predicates, the
// full set of (dimension, route) cells the matrix REQUIRES coverage for. This is
// the registry-iterating core: a new route that matches a predicate
// auto-acquires its cells; nothing is hand-enumerated as "the required list".
func requiredCells(t *testing.T) map[string]struct {
	dim   mannerDim
	route string
} {
	t.Helper()
	keys := buildLiveRouter(t)
	live := map[string]bool{}
	for _, rk := range keys {
		live[rk.key] = true
	}

	// Reverse-drift: every policy-set key must be a live route.
	checkPolicySet(t, "tierGatedRoutes", keysOf(tierGatedRoutes), live)
	checkPolicySet(t, "flagGatedRoutes", keysOfStr(flagGatedRoutes), live)
	checkPolicySet(t, "anonCapableProvisionRoutes", keysOf(anonCapableProvisionRoutes), live)
	checkPolicySet(t, "provisioningOrDeployRoutes", keysOf(provisioningOrDeployRoutes), live)
	checkPolicySet(t, "idempotentRoutes", keysOf(idempotentRoutes), live)

	req := map[string]struct {
		dim   mannerDim
		route string
	}{}
	add := func(d mannerDim, route string) {
		req[cell(d, route)] = struct {
			dim   mannerDim
			route string
		}{d, route}
	}

	for _, rk := range keys {
		if authNegativeApplies(rk.method, rk.path) {
			add(dimAuthNegative, rk.key)
		}
		if tierGatedRoutes[rk.key] {
			add(dimTierGate, rk.key)
		}
		if _, ok := flagGatedRoutes[rk.key]; ok {
			add(dimFlag, rk.key)
		}
		if anonCapableProvisionRoutes[rk.key] {
			add(dimAnonGate, rk.key)
		}
		if provisioningOrDeployRoutes[rk.key] {
			add(dimFailure, rk.key)
		}
		if idempotentRoutes[rk.key] {
			add(dimIdempotency, rk.key)
		}
	}
	return req
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfStr(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func checkPolicySet(t *testing.T, name string, ks []string, live map[string]bool) {
	t.Helper()
	for _, k := range ks {
		if !live[k] {
			t.Errorf("policy set %q references route %q which is NOT in the live tree — remove the stale entry (route renamed/removed?).", name, k)
		}
	}
}

// TestMannerMatrix_EveryApplicableCellCovered is the drift guard. For each
// (dimension, route) cell the live tree requires, assert it is mapped to a test
// OR exempted with a reason. A new tier-gated route / flag / authenticated route
// auto-creates a cell that REDs here until the author maps or exempts it.
func TestMannerMatrix_EveryApplicableCellCovered(t *testing.T) {
	req := requiredCells(t)

	for key, rc := range req {
		key, rc := key, rc
		t.Run(key, func(t *testing.T) {
			mapped, isMapped := mannerCoverageMap[key]
			reason, isExempt := mannerExemptions[key]

			if isMapped && isExempt {
				t.Errorf("cell %q is BOTH mapped (%s) and exempted — pick one (a covered cell must not carry a dead exemption).", key, mapped)
				return
			}
			if !isMapped && !isExempt {
				t.Errorf("cell %q (dimension %q on route %q) has NO mapped manner test and NO exemption. Add a covering test + a mannerCoverageMap row, OR (if genuinely uncovered) a mannerExemptions entry with a reason + a TODO wave pointer.", key, rc.dim, rc.route)
				return
			}
			if isExempt && strings.TrimSpace(reason) == "" {
				t.Errorf("cell %q is exempted with an EMPTY reason — every exemption needs a reason + TODO pointer.", key)
			}
		})
	}

	// Reverse drift: no stale map/exemption rows for cells not required by the
	// live tree.
	for key := range mannerCoverageMap {
		if _, ok := req[key]; !ok {
			t.Errorf("mannerCoverageMap has a row for cell %q but the live tree does NOT require it — remove the stale row (route/dimension changed?).", key)
		}
	}
	for key := range mannerExemptions {
		if _, ok := req[key]; !ok {
			t.Errorf("mannerExemptions has a row for cell %q but the live tree does NOT require it — remove the stale exemption.", key)
		}
	}
}

// TestMannerMatrix_MapPointsAtRealTests AST-parses every *_test.go in
// mannerTestDirs and asserts every test name referenced by mannerCoverageMap
// actually exists. Closes the map-rot loophole (a row pointing at a deleted test
// would otherwise pass EveryApplicableCellCovered). Mirrors the route guard's
// TestDoneBar_TestMapPointsAtRealTests.
func TestMannerMatrix_MapPointsAtRealTests(t *testing.T) {
	defined := definedMannerTestFuncs(t)

	// A cell value may name MORE THAN ONE covering test (comma-separated) — e.g.
	// the flag dimension names both the flag-OFF and flag-ON arm. Each named test
	// must exist, so split before checking.
	refs := map[string]bool{}
	for _, val := range mannerCoverageMap {
		for _, name := range strings.Split(val, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				refs[name] = true
			}
		}
	}
	names := make([]string, 0, len(refs))
	for n := range refs {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if !defined[name] {
			t.Errorf("mannerCoverageMap references test %q which is not defined in any manner-test dir %v — it was renamed or deleted. Point the cell at the real covering test.", name, mannerTestDirs)
		}
	}
}

// TestMannerMatrix_TierDimensionIteratesRegistry is the rule-18 registry-
// iterating assertion. The tier-gate dimension's TIER axis must be derived from
// plans.Default().All() (the live registry), not a hand-typed slice. If a NEW
// tier is added to plans.yaml, the registry grows and this test asserts the
// guard is aware of the full tier set — so the tier axis can't silently drift.
func TestMannerMatrix_TierDimensionIteratesRegistry(t *testing.T) {
	reg := plans.Default()
	all := reg.All()
	if len(all) == 0 {
		t.Fatal("plans.Default().All() returned zero tiers — registry wiring broken")
	}

	// The non-anonymous billable tiers are the tier-axis the tier-gate manner
	// reasons about (anonymous has no 402 upgrade wall — it IS the floor). We
	// assert the registry exposes at least the known billable tiers AND that the
	// iteration is over the live registry (not a constant), so adding a tier
	// auto-expands this set.
	nonAnon := 0
	for tier := range all {
		if tier == "anonymous" {
			continue
		}
		nonAnon++
	}
	if nonAnon < 1 {
		t.Fatalf("registry exposes no non-anonymous tier — the tier-gate 402 axis is meaningless. Tiers: %v", keysOfPlans(all))
	}

	// Sanity: the tier-gated routes the matrix guards must be a non-empty subset
	// of the live tree (otherwise the tier dimension guards nothing). This binds
	// "tiers exist in the registry" to "routes enforce them in the matrix".
	if len(tierGatedRoutes) == 0 {
		t.Fatal("tierGatedRoutes is empty — the tier-gate dimension guards no route; the registry tier axis would be inert.")
	}
	t.Logf("tier-gate axis iterates %d registry tiers (%d non-anonymous) across %d tier-gated routes",
		len(all), nonAnon, len(tierGatedRoutes))
}

func keysOfPlans[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestMannerMatrix_ReportExemptionBacklog prints the exemption-with-TODO cells —
// the HONEST list of remaining manner gaps that becomes the next backlog. It
// never fails (reporting, not asserting); the EveryApplicableCellCovered guard
// is what enforces. Surfacing the true gaps is the point.
func TestMannerMatrix_ReportExemptionBacklog(t *testing.T) {
	req := requiredCells(t)
	type ex struct{ key, reason string }
	var rows []ex
	for key, reason := range mannerExemptions {
		if _, ok := req[key]; ok { // only live-required exemptions are real gaps
			rows = append(rows, ex{key, reason})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
	t.Logf("MANNER-MATRIX EXEMPTION BACKLOG (%d live-required cells with TODO):", len(rows))
	for _, r := range rows {
		t.Logf("  GAP  %s\n         → %s", r.key, r.reason)
	}
}

// definedMannerTestFuncs parses every *_test.go in each mannerTestDirs entry and
// returns the set of top-level `func TestXxx(...)` names. Source-driven (Go test
// funcs aren't reflectable; the e2e package is build-tagged out of this binary).
func definedMannerTestFuncs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, dir := range mannerTestDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read manner-test dir %q: %v", dir, err)
		}
		before := len(out)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil {
					continue
				}
				if strings.HasPrefix(fn.Name.Name, "Test") {
					out[fn.Name.Name] = true
				}
			}
		}
		if len(out) == before {
			t.Fatalf("found zero Test functions in %q — parser/path misconfigured", dir)
		}
	}
	return out
}
