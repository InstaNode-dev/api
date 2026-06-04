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
//   4. TestDoneBar_TestMapPointsAtRealTests parses the e2e package's *_test.go
//      via go/ast and asserts every test name referenced by routeTestMap
//      actually EXISTS. Without this, the map could rot: a row could point at a
//      deleted test and TestDoneBar_EveryRouteCovered would still pass (it only
//      checks the key is present). This closes that loophole — same intent as
//      cli's TestDoneBar_TestMapPointsAtRealTests.
//
// WHY A MAP, NOT "any test mentions the path": a substring match over test
// source is a false-positive magnet (every resource test mentions "/db/new").
// The explicit map forces a human to point each route at the test that actually
// exercises its handler + auth chain + response/error contract.
//
// COVERING-TEST LAYER. routeTestMap points at the REAL-backend integration
// suite in api/e2e (//go:build e2e) — the matrix's W1–W4 "UI action -> backend
// state -> UI reflects it" surface. A few routes whose only integration cover
// lives at the handler-integration layer (e.g. /storage/:token/presign in
// package handlers) are EXEMPTED here with a justification citing that test +
// a TODO to add the e2e round-trip in the named wave; they are not silently
// "covered". The e2e directory is the single AST-scanned source of truth so
// the integrity check (§4) stays a one-directory parse.
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

// e2eTestDir is the directory (relative to this package) holding the real-
// backend integration suite whose Test funcs routeTestMap references. The
// integrity check (TestDoneBar_TestMapPointsAtRealTests) AST-parses it.
const e2eTestDir = "../../e2e"

// routeTestMap maps a live route key ("POST /db/new") to the name of the
// integration Test function (in package e2e) that provides its contract
// coverage. EVERY route in the live tree must appear here OR in
// routeCoverageExemptions. Adding a route without an entry in one of the two
// fails TestDoneBar_EveryRouteCovered.
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

	// ── billing (W3) ─────────────────────────────────────────────────────────
	"POST /billing/checkout":        "TestE2E_Persona_Security_BillingCheckout_InvalidPlan",
	"POST /api/v1/billing/checkout": "TestE2E_Persona_Security_BillingCheckout_InvalidPlan",
	"POST /razorpay/webhook":        "TestE2E_PlanUpgrade_SubscriptionCharged_UpdatesTier",
	"GET /api/v1/billing":           "TestE2E_FullCustomerFlow_AnonymousToProToCancelled",

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

	// ── teams / invitations: public-but-404 contract (merged surfaces) ───────
	"POST /api/v1/invitations/:token/accept":  "TestMerged_Teams_AcceptInvitation_PublicWith404",
	"GET /api/v1/teams/:team_id/invitations":  "TestMerged_Teams_InvitationsRequireAuth",
	"POST /api/v1/teams/:team_id/invitations": "TestMerged_Teams_InvitationsRequireAuth",

	// ── vault: requires-auth contract (merged surfaces) ──────────────────────
	"GET /api/v1/vault/:env":      "TestMerged_Vault_RequiresAuth",
	"GET /api/v1/vault/:env/:key": "TestMerged_Vault_RequiresAuth",
	"PUT /api/v1/vault/:env/:key": "TestMerged_Vault_RequiresAuth",
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
	"GET /api/v1/incidents":         "status-page incidents feed (read-only). TODO: matrix W7 status-surface smoke.",

	// ── approve link (deploy/quota approval) — no e2e yet.
	"GET /approve/:token": "approval-link landing — no integration test yet. TODO: matrix W4 deploy-approval flow.",

	// ── auth: account-deletion confirm link — no e2e yet.
	"GET /auth/email/confirm-deletion": "magic-link account/team deletion confirm — no e2e yet. TODO: matrix W1 deletion-confirm flow.",

	// ── experiments / analytics ingest — fire-and-forget.
	"POST /api/v1/experiments/converted": "client-side experiment conversion ping (analytics). TODO: matrix W8 analytics-surface smoke.",

	// ── usage wall (org-wide usage rollup) — no dedicated e2e.
	"GET /api/v1/usage/wall": "org usage rollup (aggregation; memory feedback_caching_and_consistency). TODO: matrix W3 usage-surface test.",

	// ── resources: family / twin / pause-resume / backup-restore (W5 lifecycle).
	"GET /api/v1/resources/families":            "resource-family grouping read. TODO: matrix W5 resource-family lifecycle.",
	"GET /api/v1/resources/:id/family":          "single-resource family view. TODO: matrix W5 resource-family lifecycle.",
	"POST /api/v1/resources/:id/provision-twin": "env-twin provisioning. TODO: matrix W5 resource-twin lifecycle.",
	"POST /api/v1/families/bulk-twin":           "bulk family twin. TODO: matrix W5 resource-twin lifecycle.",
	"POST /api/v1/resources/:id/pause":          "resource pause. TODO: matrix W5 pause/resume lifecycle.",
	"POST /api/v1/resources/:id/resume":         "resource resume. TODO: matrix W5 pause/resume lifecycle.",
	"POST /api/v1/resources/:id/backup":         "on-demand backup. TODO: matrix W5 backup/restore lifecycle (rule 24 drill is separate).",
	"GET /api/v1/resources/:id/backups":         "backup list. TODO: matrix W5 backup/restore lifecycle.",
	"POST /api/v1/resources/:id/restore":        "restore from backup. TODO: matrix W5 backup/restore lifecycle.",
	"GET /api/v1/resources/:id/restores":        "restore-job list. TODO: matrix W5 backup/restore lifecycle.",

	// ── deployments: env / patch / ttl / make-permanent / events / github.
	"PATCH /deploy/:id/env":                       "deploy env merge. TODO: matrix W4 deploy-env flow.",
	"POST /deploy/:id/redeploy":                   "deploy redeploy. TODO: matrix W4 deploy-redeploy flow.",
	"PATCH /api/v1/deployments/:id":               "deployment patch. TODO: matrix W4 deploy-patch flow.",
	"POST /api/v1/deployments/:id/make-permanent": "promote TTL deploy to permanent. TODO: matrix W4 deploy-ttl flow.",
	"POST /api/v1/deployments/:id/ttl":            "set deploy TTL. TODO: matrix W4 deploy-ttl flow.",
	"GET /api/v1/deployments/:id/events":          "failure-timeline read surface (#200). TODO: matrix W4 deploy-events flow.",
	"GET /api/v1/deployments/:id/github":          "deploy GitHub link read. TODO: matrix W4 deploy-github flow.",
	"POST /api/v1/deployments/:id/github":         "deploy GitHub link write. TODO: matrix W4 deploy-github flow.",
	"DELETE /api/v1/deployments/:id/github":       "deploy GitHub unlink. TODO: matrix W4 deploy-github flow.",

	// ── github app integration (install / callback / webhooks).
	"GET /integrations/github/install":  "GitHub App install redirect. TODO: matrix W6 github-app flow.",
	"GET /integrations/github/callback": "GitHub App OAuth callback. TODO: matrix W6 github-app flow.",
	"POST /webhooks/github":             "GitHub App webhook (no id). TODO: matrix W6 github-app webhook flow.",
	"POST /webhooks/github/:webhook_id": "GitHub App webhook (per-install). TODO: matrix W6 github-app webhook flow.",

	// ── stacks: confirm-deletion / promote / family / domains (W4 advanced).
	"PATCH /stacks/:slug/env":                      "stack env merge (mig 062). TODO: matrix W4 stack-env flow.",
	"POST /api/v1/stacks/:slug/confirm-deletion":   "stack two-step delete (confirm). TODO: matrix W4 stack-delete-twostep.",
	"DELETE /api/v1/stacks/:slug/confirm-deletion": "stack two-step delete (cancel). TODO: matrix W4 stack-delete-twostep.",
	"POST /api/v1/stacks/:slug/promote":            "stack env promote. TODO: matrix W4 stack-promote flow.",
	"GET /api/v1/stacks/:slug/family":              "stack family view. TODO: matrix W4 stack-family flow.",
	"POST /api/v1/stacks/:slug/domains":            "stack custom-domain add (Pro+). TODO: matrix W4 custom-domain flow.",
	"GET /api/v1/stacks/:slug/domains":             "stack custom-domain list. TODO: matrix W4 custom-domain flow.",
	"POST /api/v1/stacks/:slug/domains/:id/verify": "custom-domain verify. TODO: matrix W4 custom-domain flow.",
	"DELETE /api/v1/stacks/:slug/domains/:id":      "custom-domain delete. TODO: matrix W4 custom-domain flow.",

	// ── team management (members / invitations / env-policy / settings).
	"GET /api/v1/team":                                      "team detail. TODO: matrix W3 team-management flow.",
	"PATCH /api/v1/team":                                    "team rename/update. TODO: matrix W3 team-management flow.",
	"DELETE /api/v1/team":                                   "team self-delete (two-step). TODO: matrix W3 team-deletion flow.",
	"POST /api/v1/team/restore":                             "team undelete. TODO: matrix W3 team-deletion flow.",
	"GET /api/v1/team/summary":                              "team dashboard summary (aggregation). TODO: matrix W3 team-summary flow.",
	"GET /api/v1/team/settings":                             "team settings read. TODO: matrix W3 team-settings flow.",
	"PATCH /api/v1/team/settings":                           "team settings write. TODO: matrix W3 team-settings flow.",
	"GET /api/v1/team/env-policy":                           "team env-policy read. TODO: matrix W3 env-policy flow.",
	"PUT /api/v1/team/env-policy":                           "team env-policy write. TODO: matrix W3 env-policy flow.",
	"GET /api/v1/team/members":                              "team member list. TODO: matrix W3 team-members flow.",
	"POST /api/v1/team/members/invite":                      "invite member. TODO: matrix W3 team-members flow.",
	"POST /api/v1/team/members/leave":                       "leave team. TODO: matrix W3 team-members flow.",
	"DELETE /api/v1/team/members/:user_id":                  "remove member. TODO: matrix W3 team-members flow.",
	"PATCH /api/v1/team/members/:user_id":                   "change member role. TODO: matrix W3 team-members flow.",
	"POST /api/v1/team/members/:user_id/promote-to-primary": "promote member to primary owner. TODO: matrix W3 team-members flow.",
	"GET /api/v1/team/invitations":                          "pending invitation list. TODO: matrix W3 team-invitations flow.",
	"DELETE /api/v1/team/invitations/:id":                   "revoke invitation. TODO: matrix W3 team-invitations flow.",
	"POST /api/v1/team/invitations/:id/accept":              "accept invitation (authed). TODO: matrix W3 team-invitations flow.",
	"DELETE /api/v1/teams/:team_id/invitations/:id":         "revoke team invitation (plural-teams alias). TODO: matrix W3 team-invitations flow.",

	// ── billing: invoices / update-payment / change-plan / promotion / usage.
	"GET /api/v1/billing/invoices":            "invoice list. TODO: matrix W3 billing-invoices flow.",
	"GET /api/v1/billing/usage":               "billing usage rollup (aggregation). TODO: matrix W3 billing-usage flow.",
	"POST /api/v1/billing/update-payment":     "update payment method. TODO: matrix W3 billing-payment flow.",
	"POST /api/v1/billing/change-plan":        "self-serve plan change (NO downgrade — memory project_no_self_serve_cancel_downgrade). TODO: matrix W3 plan-change flow.",
	"POST /api/v1/billing/promotion/validate": "promo-code validation. TODO: matrix W3 promo-code flow.",

	// ── api keys (W3 auth tokens).
	"POST /api/v1/auth/api-keys":       "create API key. TODO: matrix W3 api-keys flow.",
	"GET /api/v1/auth/api-keys":        "list API keys. TODO: matrix W3 api-keys flow.",
	"DELETE /api/v1/auth/api-keys/:id": "revoke API key. TODO: matrix W3 api-keys flow.",

	// ── audit log read surfaces.
	"GET /api/v1/audit":     "audit-log read. TODO: matrix W3 audit-surface flow.",
	"GET /api/v1/audit.csv": "audit-log CSV export. TODO: matrix W3 audit-surface flow.",

	// ── webhook requests inspector.
	"GET /api/v1/webhooks/:token/requests": "captured webhook-request inspector. TODO: matrix W2 webhook-inspector flow.",

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

	// ── vault rotate / copy (vault read/write contract is mapped).
	"POST /api/v1/vault/:env/:key/rotate": "vault secret rotate (read/write contract mapped via TestMerged_Vault_RequiresAuth). TODO: matrix W3 vault-rotate flow.",
	"DELETE /api/v1/vault/:env/:key":      "vault secret delete. TODO: matrix W3 vault-delete flow.",
	"POST /api/v1/vault/copy":             "vault cross-env copy. TODO: matrix W3 vault-copy flow.",
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
	defined := definedE2ETestFuncs(t)

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
			t.Errorf("routeTestMap references test %q which is not defined in package e2e (%s) — it was renamed or deleted. Point the row at the real covering test.", name, e2eTestDir)
		}
	}
}

// definedE2ETestFuncs parses every *_test.go in the e2e directory and returns
// the set of top-level `func TestXxx(...)` names. Source-driven (not
// reflection) because Go test functions aren't reflectable, and because the e2e
// package is build-tagged out of this binary.
func definedE2ETestFuncs(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}

	entries, err := os.ReadDir(e2eTestDir)
	if err != nil {
		t.Fatalf("read e2e dir %q: %v", e2eTestDir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(e2eTestDir, e.Name())
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
	if len(out) == 0 {
		t.Fatalf("found zero Test functions in %q — parser/path misconfigured", e2eTestDir)
	}
	return out
}
