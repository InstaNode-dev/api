package router_test

// route_donebar_guard_test.go — the api "done-bar" route-coverage drift guard.
//
// USER-FLOW-INVENTORY-AND-TEST-MATRIX.md (2026-06-04), §0 ground-rule 5 + §4:
//   "Registry-iterating, not hand-typed (rule 18). The done-bar test iterates
//    the live route table ... and FAILS if any surface has no mapped test."
//
// This is the api-side mirror of the registry-iterating guards already merged
// in cli #25 (cmd/donebar_command_coverage_test.go), mcp #37, and provisioner
// #48. It is the structural defense against the login-outage / silent-untested-
// route / Team-buyable classes (CLAUDE.md rules 16–18, 26): a NEW HTTP route
// cannot ship "covered" by accident.
//
// HOW IT WORKS
//
//   1. Build the LIVE Fiber router (router.New) and walk its registered routes
//      via app.GetRoutes(true) — filterUse=true drops the app.Use middleware
//      fan-out so we see only real, terminal routes (the same set a client can
//      actually hit). HEAD is skipped (Fiber auto-registers it alongside GET).
//
//   2. For every (METHOD, PATH) route, assert it is EITHER
//        (a) mapped to a covering integration test in routeTestMap
//            (METHOD PATH -> e2e Test func name), OR
//        (b) listed in routeCoverageExemptions with a one-line justification +
//            a TODO pointer to the matrix wave that will cover it.
//      A route that is NEITHER mapped NOR exempt REDs the test, naming the
//      route ("route X has no mapped test and no exemption").
//
//   3. Reverse drift check: every routeTestMap / routeCoverageExemptions key
//      must correspond to a route that is actually in the live tree. A stale
//      row (route renamed/removed) is itself drift and REDs.
//
//   4. TestDoneBar_TestMapPointsAtRealTests parses every *_test.go in
//      mappedTestDirs (api/e2e + api/internal/handlers) via go/ast and asserts
//      every test name referenced by routeTestMap actually EXISTS. Without
//      this, the map could rot: a row could point at a deleted test and
//      TestDoneBar_EveryRouteCovered would still pass (it only checks the key
//      is present). This closes that loophole — same intent as cli's
//      TestDoneBar_TestMapPointsAtRealTests.
//
// WHY A MAP, NOT "any test mentions the path": a substring match over test
// source is a false-positive magnet (every resource test mentions "/db/new").
// The explicit map forces a human to point each route at the test that actually
// exercises its handler + auth chain + response/error contract.
//
// COVERING-TEST LAYER. routeTestMap points at the REAL-backend integration
// suites in mappedTestDirs:
//   - api/e2e (//go:build e2e) — the matrix's W1–W4 black-box "UI action ->
//     backend state -> UI reflects it" round-trips; and
//   - api/internal/handlers — the DB-backed handler-integration suites
//     (testhelpers.SetupTestDB + the production RequireAuth/RequireRole chain),
//     where the W3 team/member-management block is exercised against a real
//     Postgres.
// A route whose authz + state-change contract is proven at the handler-
// integration layer is genuinely covered, so its row points there rather than
// carrying an exemption. Routes with no integration cover at all stay in
// routeCoverageExemptions with a justification + TODO matrix-wave pointer.
//
// This is a pure descriptor + source-scan test: it builds the router in-memory
// (no DB/Redis/network — route registration issues no queries) and parses files
// off disk. It runs in the -short build-and-test gate and never flakes.

import (
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"instant.dev/internal/email"
	"instant.dev/internal/plans"
	"instant.dev/internal/router"
)

// mappedTestDirs are the directories (relative to this package) holding the
// integration suites whose Test funcs routeTestMap references. The integrity
// check (TestDoneBar_TestMapPointsAtRealTests) AST-parses every one.
//
//   - ../../e2e            — the black-box real-backend HTTP suite (W1–W4
//     liveness/provision/onboarding/deploy round-trips). Build-tagged
//     //go:build e2e; go/parser ignores build tags so it parses fine here.
//   - ../handlers          — the DB-backed handler-integration suites
//     (testhelpers.SetupTestDB + the production middleware chain). The W3
//     billing-block and team-block suites live here: a route whose authz +
//     state-change contract is exercised against a real Postgres through
//     RequireAuth/RequireRole is genuinely covered, so its routeTestMap row
//     points at the handler test, not a black-box probe.
//
// Both directories are AST-scanned into one defined-test set, so a row may
// point at a test in either suite. This keeps the guard honest about coverage
// that lives at the handler-integration layer (W3 team/member management)
// without forcing a black-box e2e round-trip to exist first.
var mappedTestDirs = []string{"../../e2e", "../handlers"}

// routeTestMap maps a live route key ("POST /db/new") to the name of the
// integration Test function (in one of the mappedTestDirs suites — package
// e2e or package handlers) that provides its contract coverage. EVERY route in
// the live tree must appear here OR in routeCoverageExemptions. Adding a route
// without an entry in one of the two fails TestDoneBar_EveryRouteCovered.
var routeTestMap = map[string]string{
	// ── liveness / health / discovery (public, unauth) ───────────────────────
	"GET /livez":               "TestE2E_Healthz_ReturnsOK",
	"GET /healthz":             "TestE2E_Healthz_ReturnsOK",
	"GET /readyz":              "TestE2EReadyz_AllServices_RespondWithCorrectShape",
	"GET /openapi.json":        "TestMerged_OpenAPIIncludesVaultRoutes",
	"GET /metrics":             "TestE2E_MetricsEndpoint_ReturnsPrometheusText",
	"GET /api/v1/capabilities": "TestE2E_TierMechanics_C1_LimitProgressionAcrossTiers",
	"GET /api/v1/status":       "TestE2E_Healthz_ReturnsOK",
	"GET /.well-known/oauth-protected-resource": "TestMerged_WellKnown_OAuthProtectedResource",

	// ── anonymous provisioning (W2) ──────────────────────────────────────────
	"POST /db/new":      "TestE2E_DBProvision_Returns201",
	"POST /vector/new":  "TestE2E_DBProvision_Returns201",
	"POST /cache/new":   "TestE2E_CacheProvision_Returns201",
	"POST /nosql/new":   "TestE2E_NoSQLProvision_Returns201",
	"POST /queue/new":   "TestE2E_Queue_ServiceDisabled_Or_ValidShape",
	"POST /storage/new": "TestE2E_Storage_ServiceDisabled_Or_ValidShape",
	"POST /webhook/new": "TestE2E_Webhook_ServiceDisabled_Or_ValidShape",

	// webhook receive sink (app.All fan-out; GET+POST are the documented verbs).
	"POST /webhook/receive/:token": "TestE2E_Webhook_ReceiveURL_AcceptsPost",
	"GET /webhook/receive/:token":  "TestE2E_Webhook_ReceiveURL_AcceptsPost",

	// ── onboarding / claim (W2) ──────────────────────────────────────────────
	"GET /start":         "TestE2E_StartLanding_ValidJWT_Returns302Redirect",
	"GET /claim/preview": "TestE2E_Persona_Onboarding_ClaimValidatesEmail",
	"POST /claim":        "TestE2E_Claim_Success_Returns201WithTeamID",

	// ── auth: magic-link, github, cli device-flow, session (W1) ──────────────
	"POST /auth/email/start":    "TestE2E_Persona_Onboarding_ClaimValidatesEmail",
	"GET /auth/email/callback":  "TestE2E_AuthFlow_AuthMe_ValidSession_ReturnsTierAndEmail",
	"POST /auth/github":         "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",
	"GET /auth/github/start":    "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",
	"GET /auth/github/callback": "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",
	"POST /auth/exchange":       "TestE2E_AuthFlow_AuthMe_ValidSession_ReturnsTierAndEmail",
	"POST /auth/logout":         "TestE2E_AuthFlow_AuthMe_NoAuth_Returns401",
	"GET /auth/me":              "TestE2E_AuthFlow_AuthMe_ValidSession_ReturnsTierAndEmail",
	"POST /auth/cli":            "TestE2E_Persona_CLIDeviceFlow_CreateAndPollSession",
	"GET /auth/cli/:id":         "TestE2E_Persona_CLIDeviceFlow_GetCurrentUser_NoAuth",

	// ── management API: identity + resources (W2/W3) ─────────────────────────
	"GET /api/v1/whoami":                            "TestE2E_FullCustomerFlow_WhoamiBeforeClaim",
	"GET /api/v1/resources":                         "TestE2E_ResourceLifecycle_ProvisionThenList_ItemPresent",
	"GET /api/v1/resources/:id":                     "TestE2E_ResourceLifecycle_Get_ShapeIsCorrect",
	"GET /api/v1/resources/:id/credentials":         "TestE2E_ResourceLifecycle_Get_ConnectionURLNeverLeaks",
	"GET /api/v1/resources/:id/metrics":             "TestE2E_QuotaBoundary_ResourceGet_StorageBytesField_Present",
	"DELETE /api/v1/resources/:id":                  "TestE2E_ResourceLifecycle_Delete_ResourceDisappears",
	"POST /api/v1/resources/:id/rotate-credentials": "TestE2E_RotateCredentials_Authenticated",
	"GET /resources/:token/logs":                    "TestE2E_Logs_GrowthPostgres_ReturnsLines",

	// ── resources: lifecycle (W5) — family / twin / pause-resume / backup-
	// restore. DB-backed handler-integration suites drive each route through
	// the production RequireAuth + PopulateTeamRole stack
	// (testhelpers.NewTestApp / NewTestAppWithServices rebuild the same route
	// registrations as router.go) against a real Postgres. Each row points at
	// the happy-path test that asserts the route's real contract (pause flips
	// status, backup/restore enqueue a 'pending' row for the worker, family
	// reads group by env). Tier-gate 402 + cross-team 404 + invalid-id 400 +
	// bad-state 409 are covered alongside in the same per-handler suites
	// (resource_pause_test.go, backup_test.go, twin_test.go,
	// family_bulk_twin_test.go, resource_family_test.go); the non-owner-member
	// role axis + registry-iterating unauth/cross-team sweeps live in
	// resources_lifecycle_block_integration_test.go (TestResourcesLifecycleBlock_*).
	// The twin / bulk-twin PROVISIONING leg needs a live postgres-customers
	// backend — those happy-path tests assert the auth+ownership+tier contract
	// and skip the provisioned-row assertion when the backend is unreachable
	// (deferred to the api/e2e live-cluster specs). Moved here from
	// routeCoverageExemptions.
	"GET /api/v1/resources/families":            "TestResourceFamilies_ListGroupsCorrectly",
	"GET /api/v1/resources/:id/family":          "TestResourceFamily_ThreeMembers_ReturnedInOrder",
	"POST /api/v1/resources/:id/provision-twin": "TestResourceProvisionTwin_Pro_HappyPath_Returns201",
	"POST /api/v1/families/bulk-twin":           "TestBulkTwin_HappyPath_ThreePostgresParents",
	"POST /api/v1/resources/:id/pause":          "TestResourcesLifecycleBlock_Member_PauseResume",
	"POST /api/v1/resources/:id/resume":         "TestResourcesLifecycleBlock_Member_PauseResume",
	"POST /api/v1/resources/:id/backup":         "TestResourcesLifecycleBlock_Member_BackupAndList",
	"GET /api/v1/resources/:id/backups":         "TestResourcesLifecycleBlock_Member_BackupAndList",
	"POST /api/v1/resources/:id/restore":        "TestResourcesLifecycleBlock_Member_RestoreAndList",
	"GET /api/v1/resources/:id/restores":        "TestResourcesLifecycleBlock_Member_RestoreAndList",

	// ── billing (W3) ─────────────────────────────────────────────────────────
	"POST /billing/checkout":        "TestE2E_Persona_Security_BillingCheckout_InvalidPlan",
	"POST /api/v1/billing/checkout": "TestE2E_Persona_Security_BillingCheckout_InvalidPlan",
	"POST /razorpay/webhook":        "TestE2E_PlanUpgrade_SubscriptionCharged_UpdatesTier",
	"GET /api/v1/billing":           "TestE2E_FullCustomerFlow_AnonymousToProToCancelled",

	// ── billing: invoices / usage / update-payment / change-plan / promotion
	// (W3 §E) — DB-backed handler-integration suites. The three Razorpay-portal
	// endpoints drive the route through a FAKE handlers.BillingPortal injected
	// via handlers.SetBillingPortalForTestPortal (never a live Razorpay call —
	// the external leg is deferred to the live-cluster e2e): each row points at
	// the success + circuit-open + razorpay-error arms.
	//   - invoices/update-payment/change-plan → billing_portal_arms_bvwave_test.go
	//     (TestBilling_*_PortalArms_bvwave). change-plan's success subtest is the
	//     valid hobby→pro upgrade against a real seeded team row; the
	//     no-downgrade / same-plan / Team-not-buyable policy is additionally
	//     pinned by the W3 billing-block suite
	//     (billing_block_no_cancel_downgrade_test.go,
	//     TestBillingBlock_ChangePlanRejectsDowngrade).
	//   - usage → the production-auth-chain integration suite
	//     billing_apikeys_audit_block_integration_test.go (TestBAAUsage_*: real
	//     Postgres + RequireAuth, happy path + member authz + cross-team
	//     isolation); cache-hit / redis-down fail-open / per-team cache scoping
	//     are covered alongside in billing_usage_test.go.
	//   - promotion/validate → billing_promotion_test.go
	//     (TestValidatePromotion_ValidCode_ReturnsDiscount: valid-code discount
	//     shape; invalid/wrong-plan/expired/rate-limit/401 arms in the same
	//     suite). Moved here from routeCoverageExemptions.
	"GET /api/v1/billing/invoices":            "TestBilling_ListInvoicesAPI_PortalArms_bvwave",
	"POST /api/v1/billing/update-payment":     "TestBilling_UpdatePaymentMethodAPI_PortalArms_bvwave",
	"POST /api/v1/billing/change-plan":        "TestBilling_ChangePlanAPI_PortalArms_bvwave",
	"GET /api/v1/billing/usage":               "TestBAAUsage_HappyPath_RealDB",
	"POST /api/v1/billing/promotion/validate": "TestValidatePromotion_ValidCode_ReturnsDiscount",

	// ── api keys (W3 auth tokens) — DB-backed handler-integration suites driven
	// through the production middleware.RequireAuth chain with real session JWTs
	// against a real Postgres. The CRUD round-trip (create returns plaintext
	// once → list shows metadata-only → revoke flips revoked=true) is
	// api_keys_coverage_test.go (TestAPIKeys_CreateListRevoke_HappyPath); the
	// PAT-cannot-mint / scope-subset / admin-reauth arms are
	// api_keys_authp0_test.go; and the cross-team isolation + non-owner-member +
	// unauth-401 axes are billing_apikeys_audit_block_integration_test.go
	// (TestBAAApiKeys_*). Moved here from routeCoverageExemptions.
	"POST /api/v1/auth/api-keys":       "TestAPIKeys_CreateListRevoke_HappyPath",
	"GET /api/v1/auth/api-keys":        "TestAPIKeys_CreateListRevoke_HappyPath",
	"DELETE /api/v1/auth/api-keys/:id": "TestAPIKeys_CreateListRevoke_HappyPath",

	// ── audit log read surfaces (W7-C) — DB-backed handler-integration suite
	// (audit_export_test.go) driving both endpoints through the production
	// RequireAuth chain against a real Postgres: happy path + tier-gate 402 +
	// cursor pagination + kind filter + actor-email redaction + admin.* exclusion
	// + cross-team isolation, with CSV shape parity. The non-owner-member read +
	// CSV cross-team axes are additionally pinned in
	// billing_apikeys_audit_block_integration_test.go (TestBAAAudit*). Moved here
	// from routeCoverageExemptions.
	"GET /api/v1/audit":     "TestAudit_HappyPath_ReturnsRowsForTeam",
	"GET /api/v1/audit.csv": "TestAuditCSV_Shape_HeaderAndRows",

	// ── email delivery webhooks (rule 12 truth surface) ──────────────────────
	"POST /webhooks/brevo/:secret":     "TestE2E_BrevoWebhook_DeliveredEventUpdatesLedger",
	"POST /api/v1/email/webhook/brevo": "TestE2E_BrevoWebhook_DeliveredEventUpdatesLedger",

	// ── stacks (W4) ──────────────────────────────────────────────────────────
	"POST /stacks/new":            "TestStack_AnonymousNew_Returns202",
	"GET /stacks/:slug":           "TestStack_GetNotFound",
	"GET /stacks/:slug/logs/:svc": "TestStack_Logs_AnonymousSlugNotFound_Returns404",
	"DELETE /stacks/:slug":        "TestStack_Delete",
	"POST /stacks/:slug/redeploy": "TestStack_Redeploy",
	"GET /api/v1/stacks":          "TestStack_List",
	"GET /api/v1/stacks/:slug":    "TestStack_GetWrongTeam",

	// ── stacks advanced (W4) — confirm-deletion / promote / family / domains.
	// DB-backed handler-integration suite
	// (internal/handlers/stacks_advanced_block_integration_test.go). Each row
	// points at the TestStacksAdvancedBlock_* test that drives the route through
	// the production RequireAuth + /api/v1 group (newStacksAdvancedApp mirrors
	// router.go) against a real Postgres: the route's real contract + authz
	// (owner+member 2xx, non-member cross-team 404 never 403, unauth 401) + tier
	// gate (402) + cross-team isolation. Specifically:
	//   - confirm-deletion (POST/DELETE) is the tokenized two-step delete:
	//     POST ?token CASes a pending_deletions row to 'confirmed' + tears the
	//     stack down (single-use → 410 replay; cross-team token → 410); DELETE
	//     cancels (no token; session is auth) → 'cancelled'.
	//   - promote validates env + short-circuits a NON-dev target to 202
	//     pending_approval + a promote_approvals row BEFORE any compute.
	//   - family is the Pro-gated env-family read (+ Cache-Control header).
	//   - domains create/list/verify/delete persist+read custom_domains rows;
	//     verify advances pending_verification→verified via the TXT seam. The
	//     ingress/cert legs need a live k8s and are deferred to the W4 e2e spec
	//     (asserted only up to the verified state, k8s nil). Moved here from
	//     routeCoverageExemptions.
	"POST /api/v1/stacks/:slug/confirm-deletion":   "TestStacksAdvancedBlock_ConfirmDelete_TokenizedTwoStep",
	"DELETE /api/v1/stacks/:slug/confirm-deletion": "TestStacksAdvancedBlock_ConfirmDelete_MissingTokenAndCancel",
	"POST /api/v1/stacks/:slug/promote":            "TestStacksAdvancedBlock_Promote_ApprovalGateAndAuthz",
	"GET /api/v1/stacks/:slug/family":              "TestStacksAdvancedBlock_Family_HappyAuthzAndCache",
	"POST /api/v1/stacks/:slug/domains":            "TestStacksAdvancedBlock_Domains_FullLifecycle",
	"GET /api/v1/stacks/:slug/domains":             "TestStacksAdvancedBlock_Domains_FullLifecycle",
	"POST /api/v1/stacks/:slug/domains/:id/verify": "TestStacksAdvancedBlock_Domains_FullLifecycle",
	"DELETE /api/v1/stacks/:slug/domains/:id":      "TestStacksAdvancedBlock_Domains_TierGateAndCrossTeamRow",

	// ── deploy single-app (W4 / deploy wedge) ────────────────────────────────
	"POST /deploy/new":                                "TestE2E_Deploy_RequiresAuth",
	"GET /deploy/:id":                                 "TestE2E_Deploy_RequiresAuth",
	"GET /deploy/:id/logs":                            "TestE2E_Deploy_RequiresAuth",
	"DELETE /deploy/:id":                              "TestE2E_DeleteDeploy_PaidTeam_TwoStepContract",
	"GET /api/v1/deployments":                         "TestE2E_Deploy_RequiresAuth",
	"GET /api/v1/deployments/:id":                     "TestE2E_Deploy_RequiresAuth",
	"DELETE /api/v1/deployments/:id":                  "TestE2E_DeleteDeploy_PaidTeam_TwoStepContract",
	"DELETE /api/v1/deployments/:id/confirm-deletion": "TestE2E_DeleteDeploy_PaidTeam_TwoStepContract",
	"POST /api/v1/deployments/:id/confirm-deletion":   "TestE2E_DeleteDeploy_PaidTeam_TwoStepContract",

	// ── deploy lifecycle (W4 §D5–D10) — DB-backed handler-integration suite
	// (internal/handlers/deploy_lifecycle_block_integration_test.go). Each row
	// points at the TestDeployLifecycle_* test that drives the route through the
	// production RequireAuth chain (NewTestAppWithServices mirrors router.New)
	// against a real Postgres: state-change contract + cross-team 404 + tier-gate
	// 402 + redeploy CAS guard. Heavy Kaniko-build legs assert the
	// accepted/contract surface (noop compute), not a live build — deferred to
	// the W4 e2e specs. Moved here from routeCoverageExemptions.
	"PATCH /deploy/:id/env":     "TestDeployLifecycle_UpdateEnv_MergesAndRedacts",
	"POST /deploy/:id/redeploy": "TestDeployLifecycle_Redeploy_HealthyRow_Accepts202",
	// Scale-to-zero explicit wake (mig 068, Task #54). Covered by the flag-ON
	// sqlmock handler suite (deploy_wake_mock_test.go): happy-path scale+DB
	// flip+re-read, not-found, cross-team 404, scale-failure 503, DB-error 503,
	// requireTeam 401, fetch driver-error 503, re-read fallback. Flag-OFF 501 is
	// in deploy_wake_test.go.
	"POST /deploy/:id/wake":                       "TestWake_HappyPath",
	"PATCH /api/v1/deployments/:id":               "TestDeployLifecycle_Patch_Pro_SetsPrivate",
	"POST /api/v1/deployments/:id/make-permanent": "TestDeployLifecycle_MakePermanent_HappyPath",
	"POST /api/v1/deployments/:id/ttl":            "TestDeployLifecycle_SetTTL_HappyPath",
	"GET /api/v1/deployments/:id/events":          "TestDeployLifecycle_Events_Timeline_OwnerReadsDescOrder",

	// ── deploy ↔ GitHub link (D17 / W6) — DB-backed handler-integration suite
	// (internal/handlers/github_deploy_block_integration_test.go). Each row
	// points at the TestGitHubDeployBlock_* test that drives the route through
	// the production RequireAuth + RequireWritable chain (NewTestAppWithServices
	// mirrors router.New) against a real Postgres: connect/get/disconnect
	// state-change + secret-once + already-connected 409 + invalid-repo 400 +
	// tier gate (hobby-allowed / anonymous-402) + authz (owner+member 2xx,
	// non-member cross-team 404, unauth 401) + cross-team isolation. Moved here
	// from routeCoverageExemptions. The PUBLIC receive endpoint
	// (/webhooks/github/:webhook_id) has no session-auth chain to drive and
	// stays exempt (its HMAC/rate-limit internals are covered by the whitebox
	// suites github_deploy_test.go + github_deploy_receive_arms_coverage_test.go).
	"POST /api/v1/deployments/:id/github":   "TestGitHubDeployBlock_Connect_OwnerHappyPath",
	"GET /api/v1/deployments/:id/github":    "TestGitHubDeployBlock_Get_ConnectedShape",
	"DELETE /api/v1/deployments/:id/github": "TestGitHubDeployBlock_Disconnect_RemovesConnection",

	// ── teams / invitations: public-but-404 contract (merged surfaces) ───────
	"POST /api/v1/invitations/:token/accept":  "TestMerged_Teams_AcceptInvitation_PublicWith404",
	"GET /api/v1/teams/:team_id/invitations":  "TestMerged_Teams_InvitationsRequireAuth",
	"POST /api/v1/teams/:team_id/invitations": "TestMerged_Teams_InvitationsRequireAuth",

	// ── team & member management (W3 §F) — DB-backed handler-integration suite
	// (internal/handlers/team_block_routes_test.go). Each row points at the
	// TestTeamBlock_* test that drives the route through the production RBAC
	// middleware chain (RequireRole/PopulateTeamRole/RequireWritable) against a
	// real Postgres: happy path + owner/member/non-member authz + cross-team
	// isolation + contract shape. Moved here from routeCoverageExemptions.
	"GET /api/v1/team":                                      "TestTeamBlock_GetTeam",
	"PATCH /api/v1/team":                                    "TestTeamBlock_PatchTeam",
	"DELETE /api/v1/team":                                   "TestTeamBlock_DeleteAndRestoreTeam",
	"POST /api/v1/team/restore":                             "TestTeamBlock_DeleteAndRestoreTeam",
	"GET /api/v1/team/summary":                              "TestTeamBlock_GetTeamSummary",
	"GET /api/v1/team/settings":                             "TestTeamBlock_TeamSettings",
	"PATCH /api/v1/team/settings":                           "TestTeamBlock_TeamSettings",
	"GET /api/v1/team/env-policy":                           "TestTeamBlock_EnvPolicy",
	"PUT /api/v1/team/env-policy":                           "TestTeamBlock_EnvPolicy",
	"GET /api/v1/team/members":                              "TestTeamBlock_ListMembers",
	"POST /api/v1/team/members/invite":                      "TestTeamBlock_InviteMember",
	"POST /api/v1/team/members/leave":                       "TestTeamBlock_LeaveTeam",
	"DELETE /api/v1/team/members/:user_id":                  "TestTeamBlock_RemoveMember",
	"PATCH /api/v1/team/members/:user_id":                   "TestTeamBlock_UpdateMemberRole",
	"POST /api/v1/team/members/:user_id/promote-to-primary": "TestTeamBlock_PromoteToPrimary",
	"GET /api/v1/team/invitations":                          "TestTeamBlock_Invitations",
	"DELETE /api/v1/team/invitations/:id":                   "TestTeamBlock_Invitations",
	"POST /api/v1/team/invitations/:id/accept":              "TestTeamBlock_AcceptInvitationByID",
	"DELETE /api/v1/teams/:team_id/invitations/:id":         "TestTeamBlock_TeamsAliasRevokeInvitation",

	// ── deploy-approval email link (W4) — DB-backed handler-integration suite
	// (internal/handlers/approve_block_routes_test.go). The public GET
	// /approve/:token landing (token IS the credential — no auth) is driven
	// through the production route wiring (approveBlockApp mirrors
	// router.go's app.Get("/approve/:token", NewPromoteApprovalHandler(db,
	// rdb).Approve)) against a real Postgres: happy path (302 → dashboard +
	// row persisted 'approved'), single-use (second click → 410), expired
	// (410 + row flipped 'expired'), invalid token (404), and the per-IP
	// rate limit (429). Moved here from routeCoverageExemptions.
	"GET /approve/:token": "TestApproveBlock_ValidPendingToken",

	// ── vault: per-team encrypted secret store (W3) — DB-backed handler-
	// integration suite (internal/handlers/vault_block_routes_test.go). Each
	// row points at the TestVaultBlock_* test that drives the route through the
	// production RequireAuth + PopulateTeamRole + RequireEnvAccess(VaultWrite)
	// chain (vaultBlockApp mirrors router.New) against a real Postgres: happy
	// path + tier/env-policy authz (403/402) + cross-team isolation (404, never
	// 403) + the encrypt/decrypt-at-rest contract + rotate/copy semantics +
	// input validation. Moved here from the shallow TestMerged_Vault_RequiresAuth
	// probe (GET/GET/PUT) and from routeCoverageExemptions (rotate/delete/copy).
	"GET /api/v1/vault/:env":              "TestVaultBlock_ListKeys",
	"GET /api/v1/vault/:env/:key":         "TestVaultBlock_GetSecret",
	"PUT /api/v1/vault/:env/:key":         "TestVaultBlock_PutSecret",
	"POST /api/v1/vault/:env/:key/rotate": "TestVaultBlock_RotateSecret",
	"DELETE /api/v1/vault/:env/:key":      "TestVaultBlock_DeleteSecret",
	"POST /api/v1/vault/copy":             "TestVaultBlock_CopySecrets",

	// ── misc surfaces (LAST real-flow wave) — DB-backed handler-integration
	// suite (internal/handlers/misc_routes_block_integration_test.go,
	// TestMiscBlock_*). Each row points at the TestMiscBlock_* test that drives
	// the route through the SAME middleware chain router.go wires (RequireAuth
	// for the /api/v1 session-gated usage-wall; OptionalAuth for the
	// token-as-credential webhook inspector; bare public registration for the
	// unauth incidents feed + the confirm-deletion redirect) against a real
	// migrated Postgres (+ Redis for the inspector's receive→store→inspect
	// round-trip). Specifically:
	//   - incidents is the read-only status-page feed ({ok,items,total,
	//     status_page}; public, no team-scoped data).
	//   - confirm-deletion is the tokenized email-link redirect (the `t=` token
	//     IS the credential): present token → 302 to the dashboard with the
	//     token carried verbatim; missing/blank token → canonical 400
	//     missing_token envelope.
	//   - usage/wall is the org usage rollup: 401 unauth, near_wall=true +
	//     flattened metadata + cache headers for a hobby team with a fresh
	//     near_quota_wall row, team-tier short-circuit, and team-scoped
	//     isolation.
	//   - webhooks/:token/requests is the captured-request inspector:
	//     token-as-bearer reads only that token's captures (cross-token
	//     isolation), invalid→400, unknown→404, cross-team session→403.
	// Moved here from routeCoverageExemptions.
	//
	// POST /api/v1/experiments/converted is mapped at the analytics-ingest
	// row below — its DB-backed, production-router contract was already covered
	// by experiments_test.go (TestExperimentsConverted_WritesAuditRow), so its
	// row points there rather than duplicating the audit round-trip.
	"GET /api/v1/incidents":                "TestMiscBlock_Incidents_PublicFeed",
	"GET /auth/email/confirm-deletion":     "TestMiscBlock_ConfirmDeletionRedirect_TokenBranches",
	"GET /api/v1/usage/wall":               "TestMiscBlock_UsageWall_RealDBContract",
	"GET /api/v1/webhooks/:token/requests": "TestMiscBlock_WebhookInspector_TokenScopedAndIsolated",
	"POST /api/v1/experiments/converted":   "TestExperimentsConverted_WritesAuditRow",

	// ── CI-only ephemeral-test-account surface (guarded; inert by default) —
	// DB-backed handler-integration suite
	// (internal/handlers/internal_e2e_account_test.go). The create row points at
	// the mint happy-path test (is_test_cohort team + email-verified primary +
	// a session JWT that authenticates through the production RequireAuth chain);
	// the reap row points at the happy-path purge test (an is_test_cohort team's
	// resources marked for the reaper + the team tombstoned). The CRITICAL safety
	// arm (a non-test-cohort real team can NEVER be reaped → 403 not_test_cohort),
	// the 404-when-inert / wrong-token guard, tier=team/growth 400, paid-tier,
	// idempotent reap, and per-token rate-limit/fail-open arms are covered in the
	// same suite (+ internal_e2e_account_errpaths_test.go for the DB/redis/sign
	// failure arms).
	"POST /internal/e2e/account":            "TestE2EAccount_Create_FreeTier_MintsTestCohortAndAuthenticatingJWT",
	"DELETE /internal/e2e/account/:team_id": "TestE2EAccount_Reap_TestCohortTeam_Purged",
}

// routeCoverageExemptions lists routes that have NO mapped e2e integration test
// yet. Each value is a one-line justification ending in a TODO pointer to the
// matrix wave that will cover it. A route that is genuinely covered elsewhere
// (handler-integration layer) cites that test. Empty justification is rejected.
//
// Exemptions are an explicit, reviewable allowlist — not a silent skip. The
// moment a wave lands the covering test, the route moves from here to
// routeTestMap (and the reverse-drift check guarantees neither map keeps a
// stale row for a deleted route).
var routeCoverageExemptions = map[string]string{
	// ── probe CORS preflight (OPTIONS) — 204 + Allow header, no business logic.
	"OPTIONS /livez":        "probe CORS preflight (probeOptionsHandler) — 204+Allow only; GET sibling is mapped. TODO: matrix W1 may add an OPTIONS assertion.",
	"OPTIONS /healthz":      "probe CORS preflight (probeOptionsHandler) — 204+Allow only; GET sibling is mapped. TODO: matrix W1 may add an OPTIONS assertion.",
	"OPTIONS /readyz":       "probe CORS preflight (probeOptionsHandler) — 204+Allow only; GET sibling is mapped. TODO: matrix W1 may add an OPTIONS assertion.",
	"OPTIONS /openapi.json": "probe CORS preflight (probeOptionsHandler) — 204+Allow only; GET sibling is mapped. TODO: matrix W1 may add an OPTIONS assertion.",

	// ── webhook/receive app.All fan-out — non-GET/POST verbs share one handler.
	"PUT /webhook/receive/:token":     "app.All fan-out — receiver accepts any verb; POST round-trip (TestE2E_Webhook_ReceiveURL_AcceptsPost) covers the handler. TODO: matrix W2 per-verb assertion.",
	"PATCH /webhook/receive/:token":   "app.All fan-out — receiver accepts any verb; POST round-trip covers the handler. TODO: matrix W2 per-verb assertion.",
	"DELETE /webhook/receive/:token":  "app.All fan-out — receiver accepts any verb; POST round-trip covers the handler. TODO: matrix W2 per-verb assertion.",
	"CONNECT /webhook/receive/:token": "app.All fan-out — receiver accepts any verb; POST round-trip covers the handler. TODO: matrix W2 per-verb assertion.",
	"TRACE /webhook/receive/:token":   "app.All fan-out — receiver accepts any verb; POST round-trip covers the handler. TODO: matrix W2 per-verb assertion.",
	"OPTIONS /webhook/receive/:token": "app.All fan-out — receiver accepts any verb; POST round-trip covers the handler. TODO: matrix W2 per-verb assertion.",

	// ── storage presign broker — covered at handler-integration layer.
	"POST /storage/:token/presign": "covered by package handlers TestPresignBlock_C16_* (broker signed-URL, TTL, cross-team reject). TODO: matrix W4 presign-broker-live.spec.ts e2e round-trip.",

	// ── content / marketing static surfaces.
	"GET /llms.txt":                 "static content redirect (built from content repo, memory project_live_llms_txt). TODO: matrix W7 content-surface smoke.",
	"GET /llms-full.txt":            "static content redirect (built from content repo). TODO: matrix W7 content-surface smoke.",
	"GET /security.txt":             "static RFC-9116 security.txt. TODO: matrix W7 content-surface smoke.",
	"GET /.well-known/security.txt": "static RFC-9116 security.txt. TODO: matrix W7 content-surface smoke.",

	// ── approve link (deploy/quota approval) — MOVED to routeTestMap. Now
	// covered by the W4 deploy-approval handler-integration suite
	// (internal/handlers/approve_block_routes_test.go, TestApproveBlock_*).

	// ── misc surfaces (incidents / confirm-deletion / usage-wall /
	// experiments-converted / webhook-inspector) — MOVED to routeTestMap. Now
	// covered by the misc-routes handler-integration suite
	// (internal/handlers/misc_routes_block_integration_test.go, TestMiscBlock_*)
	// plus the pre-existing experiments_test.go round-trip the experiments row
	// points at.

	// ── resources: family / twin / pause-resume / backup-restore (W5 lifecycle)
	// — MOVED to routeTestMap. Now covered by the DB-backed handler-integration
	// suites that drive each route through the production RequireAuth +
	// PopulateTeamRole stack (testhelpers.NewTestApp / NewTestAppWithServices
	// rebuild the same registrations as router.go) against a real Postgres.

	// ── deployments: env / patch / ttl / make-permanent / events — MOVED to
	// routeTestMap. Now covered by the W4 deploy-lifecycle handler-integration
	// suite (internal/handlers/deploy_lifecycle_block_integration_test.go,
	// TestDeployLifecycle_*). The GitHub-link rows below stay exempt (D17/W6).

	// ── deploy ↔ GitHub link (D17 / W6) — MOVED to routeTestMap. Now covered by
	// the W6 github-deploy-link handler-integration suite
	// (internal/handlers/github_deploy_block_integration_test.go,
	// TestGitHubDeployBlock_*).

	// ── github app integration (install / callback / webhooks) — kept exempt:
	// these need a real GitHub App (OAuth install redirect, signed-with-the-App-
	// secret callback/webhook) that this hermetic DB-backed suite cannot stand
	// in for. The per-connection PUBLIC receive endpoint
	// (POST /webhooks/github/:webhook_id) is auth'd by HMAC, not a session JWT,
	// so it has no RequireAuth chain to drive here; its signature / branch-match
	// / rate-limit / idempotency internals are covered by the whitebox suites
	// github_deploy_test.go + github_deploy_receive_arms_coverage_test.go.
	"GET /integrations/github/install":  "GitHub App install redirect (real GitHub OAuth). TODO: matrix W6 github-app flow (staging/e2e with a real App).",
	"GET /integrations/github/callback": "GitHub App OAuth callback (real GitHub OAuth). TODO: matrix W6 github-app flow (staging/e2e with a real App).",
	"POST /webhooks/github":             "GitHub App webhook, no id (HMAC-auth'd by the App secret, no session chain). TODO: matrix W6 github-app webhook flow.",
	"POST /webhooks/github/:webhook_id": "per-connection push receiver (HMAC-auth'd, no session chain; signature/branch/rate-limit/idempotency covered by whitebox github_deploy_test.go + github_deploy_receive_arms_coverage_test.go). TODO: matrix W6 github-app webhook e2e.",

	// ── stacks: env-merge (W4 advanced). The eight other advanced surfaces
	// (confirm-deletion ×2 / promote / family / domains ×4) — MOVED to
	// routeTestMap. Now covered by the W4 stacks-advanced handler-integration
	// suite (internal/handlers/stacks_advanced_block_integration_test.go,
	// TestStacksAdvancedBlock_*).
	"PATCH /stacks/:slug/env": "stack env merge (mig 062). TODO: matrix W4 stack-env flow.",

	// ── team & member management (members / invitations / env-policy /
	// settings / deletion) — MOVED to routeTestMap. Now covered by the
	// W3 team-block handler-integration suite
	// (internal/handlers/team_block_routes_test.go, TestTeamBlock_*).

	// ── billing: invoices / update-payment / change-plan / promotion / usage
	// + api keys (create/list/revoke) + audit (read + CSV) — MOVED to
	// routeTestMap. Now covered by the DB-backed handler-integration suites:
	// billing_portal_arms_bvwave_test.go (portal arms via the fake
	// BillingPortal), billing_promotion_test.go (promo validate),
	// api_keys_coverage_test.go + api_keys_authp0_test.go (PAT CRUD + AUTH-P0
	// arms), audit_export_test.go (audit JSON/CSV), and the production-auth-chain
	// cross-team / member-authz layer billing_apikeys_audit_block_integration_test.go
	// (TestBAA*).

	// ── webhook requests inspector — MOVED to routeTestMap. Now covered by the
	// misc-routes handler-integration suite (TestMiscBlock_WebhookInspector_*).

	// ── SES email webhook (Brevo is mapped; SES is the alternate backend).
	"POST /api/v1/email/webhook/ses":  "SES delivery webhook (alternate backend; Brevo path is mapped). TODO: matrix W7 ses-webhook flow.",
	"GET /api/v1/email/webhook/brevo": "Brevo webhook GET health-probe (POST is mapped). TODO: matrix W7 webhook-probe assertion.",
	"GET /api/v1/email/webhook/ses":   "SES webhook GET health-probe. TODO: matrix W7 webhook-probe assertion.",

	// ── dev-only / internal operator routes (not user-facing; gated).
	"POST /internal/set-tier":                      "dev-only tier override (ENVIRONMENT=development gate). TODO: matrix W9 dev-endpoint guard.",
	"POST /internal/teams/:id/terminate":           "internal team termination (operator). TODO: matrix W9 internal-ops guard.",
	"POST /internal/teams/:id/backup-quota/refund": "internal backup-quota refund (operator). TODO: matrix W9 internal-ops guard.",
	"POST /internal/email/resend-magic-link":       "internal magic-link resend (operator). TODO: matrix W9 internal-ops guard.",

	// ── admin console (AdminPathPrefix-gated; 404 by default in prod).
	"GET /api/v1/admin/customers":                       "admin customer list (path-prefix gated). TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/customers/:team_id":              "admin customer detail. TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/customers/:team_id/notes":        "admin customer notes read. TODO: matrix W10 admin-console flow.",
	"POST /api/v1/admin/customers/:team_id/notes":       "admin customer note add. TODO: matrix W10 admin-console flow.",
	"DELETE /api/v1/admin/notes/:note_id":               "admin note delete. TODO: matrix W10 admin-console flow.",
	"POST /api/v1/admin/customers/:team_id/tier":        "admin tier set. TODO: matrix W10 admin-console flow.",
	"POST /api/v1/admin/customers/:team_id/promo":       "admin promo grant. TODO: matrix W10 admin-console flow.",
	"POST /api/v1/admin/customers/:team_id/impersonate": "admin impersonation. TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/deploys":                         "admin deploy overview. TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/promotions":                      "admin promotion list. TODO: matrix W10 admin-console flow.",
	"POST /api/v1/admin/promotions/:id/reject":          "admin promotion reject. TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/promos/audit":                    "admin promo audit. TODO: matrix W10 admin-console flow.",
	"GET /api/v1/admin/promos/stats":                    "admin promo stats. TODO: matrix W10 admin-console flow.",

	// ── vault rotate / delete / copy — MOVED to routeTestMap. Now covered by
	// the W3 vault-block handler-integration suite
	// (internal/handlers/vault_block_routes_test.go, TestVaultBlock_*), which
	// also upgraded the GET/GET/PUT rows off the shallow
	// TestMerged_Vault_RequiresAuth probe to full contract coverage.
}

// buildLiveRouter constructs the production router in-memory. Route
// registration issues no DB/Redis queries, so an unpinged *sql.DB and an
// unconnected redis client are sufficient — and keep this a hermetic,
// -short-safe test (no network).
func buildLiveRouter(t *testing.T) []routeKey {
	t.Helper()

	// sql.Open does not dial; the connection is lazy and never used during
	// route registration.
	db, err := sql.Open("postgres", "postgres://donebar:donebar@127.0.0.1:5432/donebar?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open (no dial expected): %v", err)
	}
	defer db.Close()

	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
	defer rdb.Close()

	cfg := newRouterTestConfig()
	// AdminPathPrefix non-empty so the admin subtree registers (those routes
	// must be enumerated + exempted, not silently absent).
	cfg.AdminPathPrefix = "admin"
	cfg.MetricsToken = ""

	app := router.New(cfg, db, rdb, nil, email.NewNoop(), plans.Default(), nil, nil)

	seen := map[string]bool{}
	var keys []routeKey
	for _, r := range app.GetRoutes(true) { // filterUse=true → real routes only
		// HEAD is auto-registered by Fiber alongside GET; not an authored
		// surface, so exclude it from the coverage requirement.
		if r.Method == "HEAD" {
			continue
		}
		k := r.Method + " " + r.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, routeKey{method: r.Method, path: r.Path, key: k})
	}
	if len(keys) == 0 {
		t.Fatal("live router enumerated ZERO routes — GetRoutes wiring broken")
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].key < keys[j].key })
	return keys
}

type routeKey struct {
	method string
	path   string
	key    string
}

// TestDoneBar_EveryRouteCovered is the drift guard. It walks the LIVE Fiber
// route table and asserts each route is mapped to a test OR explicitly
// exempted. A new app.Get/Post/... without a routeTestMap or
// routeCoverageExemptions entry fails here, naming the route.
func TestDoneBar_EveryRouteCovered(t *testing.T) {
	keys := buildLiveRouter(t)

	live := map[string]bool{}
	for _, rk := range keys {
		live[rk.key] = true

		t.Run(rk.key, func(t *testing.T) {
			_, mapped := routeTestMap[rk.key]
			exempt, exemptedOK := routeCoverageExemptions[rk.key]

			if mapped && exemptedOK {
				t.Errorf("route %q is BOTH mapped to a test and exempted — pick one. A route that is covered should not also carry an exemption (dead justification).", rk.key)
				return
			}
			if !mapped && !exemptedOK {
				t.Errorf("route %q has no mapped test and no exemption. Add a covering integration test + a routeTestMap row, OR (if genuinely not-yet-covered) a routeCoverageExemptions entry with a one-line reason + a TODO matrix-wave pointer.", rk.key)
				return
			}
			if exemptedOK && strings.TrimSpace(exempt) == "" {
				t.Errorf("route %q is exempted with an EMPTY justification — every exemption needs a reason + TODO pointer.", rk.key)
			}
		})
	}

	// Reverse drift check: no stale map/exemption rows for routes that left the
	// tree (renamed/removed). A stale row is itself drift.
	for k := range routeTestMap {
		if !live[k] {
			t.Errorf("routeTestMap has a row for %q but that route is NOT in the live tree — remove the stale row (route renamed/removed?).", k)
		}
	}
	for k := range routeCoverageExemptions {
		if !live[k] {
			t.Errorf("routeCoverageExemptions has a row for %q but that route is NOT in the live tree — remove the stale exemption.", k)
		}
	}
}

// TestDoneBar_TestMapPointsAtRealTests asserts every test name referenced by
// routeTestMap actually exists as a `func TestXxx(t *testing.T)` in the e2e
// package. This closes the map-rot loophole: without it, a row could point at a
// deleted/renamed test and TestDoneBar_EveryRouteCovered would still pass (it
// only checks the key is present). Mirrors cli's
// TestDoneBar_TestMapPointsAtRealTests. go/parser ignores build tags, so the
// //go:build e2e files parse fine here even in the -short gate.
func TestDoneBar_TestMapPointsAtRealTests(t *testing.T) {
	defined := definedMappedTestFuncs(t)

	refs := map[string]bool{}
	for _, name := range routeTestMap {
		refs[name] = true
	}
	names := make([]string, 0, len(refs))
	for n := range refs {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		if !defined[name] {
			t.Errorf("routeTestMap references test %q which is not defined in any mapped-test dir %v — it was renamed or deleted. Point the row at the real covering test.", name, mappedTestDirs)
		}
	}
}

// definedMappedTestFuncs parses every *_test.go in each mappedTestDirs entry
// and returns the set of top-level `func TestXxx(...)` names across all of
// them. Source-driven (not reflection) because Go test functions aren't
// reflectable, and because the e2e package is build-tagged out of this binary.
func definedMappedTestFuncs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, dir := range mappedTestDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read mapped-test dir %q: %v", dir, err)
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
				name := fn.Name.Name
				if strings.HasPrefix(name, "Test") {
					out[name] = true
				}
			}
		}
		if len(out) == before {
			t.Fatalf("found zero Test functions in %q — parser/path misconfigured", dir)
		}
	}
	return out
}
