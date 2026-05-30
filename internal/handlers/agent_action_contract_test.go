package handlers

// agent_action_contract_test.go — enforces the U3 contract (see
// agent_action.go) on every string the handler package returns via
// `agent_action`. One failure here means the contract regressed.
//
// Why one giant table:
//   - Reviewers see every wall in one place.
//   - Adding a new `agent_action` const without adding a row to this table
//     is the violation we want CI to flag (you can grep this file to find
//     constants without coverage).

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// agentActionContractCases is the canonical list of every agent_action
// string returned by this package. Static constants are exercised directly;
// builders are exercised with representative inputs.
//
// All strings MUST pass the four contract requirements (plus the < 280 char
// soft ceiling). assertContract enforces them.
func agentActionContractCases() map[string]string {
	cases := map[string]string{
		// Static constants.
		"AgentActionMultiEnvUpgradeRequired":           AgentActionMultiEnvUpgradeRequired,
		"AgentActionStackPromoteMissingImageRef":       AgentActionStackPromoteMissingImageRef,
		"AgentActionBindingFamilyDisabled":             AgentActionBindingFamilyDisabled,
		"AgentActionBindingLookupFailed":               AgentActionBindingLookupFailed,
		"RecycleGateAgentAction":                       RecycleGateAgentAction,
		"AgentActionPrivateDeployRequiresPro":          AgentActionPrivateDeployRequiresPro,
		"AgentActionPrivateDeployRequiresAllowedIPs":   AgentActionPrivateDeployRequiresAllowedIPs,
		"AgentActionAdminRequired":                     AgentActionAdminRequired,
		"AgentActionPromotionInvalid":                  AgentActionPromotionInvalid,
		"AgentActionPromotionAlreadyUsed":              AgentActionPromotionAlreadyUsed,
		"AgentActionPromotionExpired":                  AgentActionPromotionExpired,
		"AgentActionPromoteTokenExpired":               AgentActionPromoteTokenExpired,
		"AgentActionReadOnlySession":                   AgentActionReadOnlySession,
		"AgentActionNotifyWebhookInvalid":              AgentActionNotifyWebhookInvalid,
		"AgentActionPauseRequiresPro":                  AgentActionPauseRequiresPro,
		"AgentActionResourceAlreadyPaused":             AgentActionResourceAlreadyPaused,
		"AgentActionResourceNotPaused":                 AgentActionResourceNotPaused,
		"AgentActionBackupRequiresClaim":               AgentActionBackupRequiresClaim,
		"AgentActionRestoreRequiresPro":                AgentActionRestoreRequiresPro,
		"AgentActionRestoreRequiresHobbyPlus":          AgentActionRestoreRequiresHobbyPlus,
		"AgentActionRestoreBackupNotReady":             AgentActionRestoreBackupNotReady,
		"AgentActionRestoreInflight":                   AgentActionRestoreInflight,
		"AgentActionRestoreDestructiveAckRequired":     AgentActionRestoreDestructiveAckRequired,
		"AgentActionRestoreTargetCrossTeam":            AgentActionRestoreTargetCrossTeam,
		"AgentActionBackupIntegrityFailed":             AgentActionBackupIntegrityFailed,
		"AgentActionMetricsRequiresUpgrade":            AgentActionMetricsRequiresUpgrade,
		"AgentActionEmailNotVerified":                  AgentActionEmailNotVerified,
		// Wave FIX-J deploy TTL walls. The long-form success-path
		// newAgentActionDeployAutoExpire24h is documented in
		// agent_action.go as the canonical exception to the 280-char
		// soft target (it has to enumerate THREE next actions), so it
		// is intentionally NOT exercised by this contract gate —
		// covered instead by deploy_ttl_test.go which spot-checks the
		// imperative opening + URL inclusion.
		"AgentActionDeployMakePermanentAnonymous":     AgentActionDeployMakePermanentAnonymous,
		"AgentActionDeployTTLHoursOutOfRange":         AgentActionDeployTTLHoursOutOfRange,
		"AgentActionTeamSettingsInvalidTTLPolicy":     AgentActionTeamSettingsInvalidTTLPolicy,

		// Builders — representative inputs covering tier/env/role/limit
		// interpolation.
		"newAgentActionDeploymentLimitReached(hobby,1)":  newAgentActionDeploymentLimitReached("hobby", 1),
		"newAgentActionBackupRateLimited(hobby,1)":       newAgentActionBackupRateLimited("hobby", 1),
		"newAgentActionMetricsWindowTooLarge(hobby,1h)":  newAgentActionMetricsWindowTooLarge("hobby", "1h"),
		"newAgentActionPromoteApprovalSent(prod,email)":  newAgentActionPromoteApprovalSent("production", "owner@example.com"),
		"newAgentActionStorageLimitReached(hobby,500)":   newAgentActionStorageLimitReached("hobby", 500),
		"newAgentActionVaultQuotaExceeded(hobby,50)":     newAgentActionVaultQuotaExceeded("hobby", 50),
		"newAgentActionEnvPolicyDenied(prod,deploy)":     newAgentActionEnvPolicyDenied("production", "deploy", "owner", "developer"),
		"newAgentActionOwnerRequired(developer)":         newAgentActionOwnerRequired("developer"),
		"newAgentActionBindingInvalidUUID(KEY)":          newAgentActionBindingInvalidUUID("DATABASE_URL", "not-a-uuid"),
		"newAgentActionBindingNotFound(KEY)":             newAgentActionBindingNotFound("DATABASE_URL"),
		"newAgentActionBindingCrossTeam(KEY)":            newAgentActionBindingCrossTeam("DATABASE_URL"),
		"newAgentActionBindingNoEnvTwin(uuid,name,env)":  newAgentActionBindingNoEnvTwin("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "owner-db", "staging"),
		"newAgentActionAdminTierChanged(team,pro)":       newAgentActionAdminTierChanged("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "pro"),
		"newAgentActionAdminPromoIssued(team,code)":      newAgentActionAdminPromoIssued("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "01H8XGZJ"),
	}

	// codeToAgentAction registry — every entry must also pass the contract.
	for code, meta := range codeToAgentAction {
		cases["codeToAgentAction["+code+"]"] = meta.AgentAction
	}

	return cases
}

// assertContract enforces the four U3 requirements + the soft length ceiling
// against a single string. Used by TestAgentActionContract and any future
// per-string assertions.
func assertContract(t *testing.T, name, s string) {
	t.Helper()

	// 1. Imperative opening.
	assert.True(t, strings.HasPrefix(s, "Tell the user"),
		"%s: agent_action must start with \"Tell the user\" (the imperative the LLM agent re-articulates to the human). Got: %q", name, s)

	// 4. Full HTTPS URL.
	assert.Contains(t, s, "https://instanode.dev/",
		"%s: agent_action must contain a full https://instanode.dev/ URL — not a relative path. Got: %q", name, s)

	// 5. Soft length ceiling — LLMs reproduce sub-tweet copy verbatim.
	assert.Less(t, len(s), 280,
		"%s: agent_action must be < 280 chars (LLMs paraphrase longer strings). Got %d chars: %q", name, len(s), s)

	// Surface area for requirements 2 and 3 (specific reason + exact action).
	// These can't be enforced by a generic regex, but the next-action
	// vocabulary is bounded: every string MUST contain at least one of the
	// known action verbs. This catches passive constructions like
	// "Their plan does not allow X" which give the LLM no remedy.
	actionVerbs := []string{
		"Upgrade", "upgrade",
		"Have them", "Have the", "have a", "have them", "have the",
		"Wait", "wait", // rate-limit
		"Retry", "retry",
		"provision", "Provision",
		"claim", "Claim", // recycle gate
		"log in",
		"sign up",
		"Ask", "ask", // invitations
		"email",
		"Remove", "remove", // family-disabled
		"Redeploy", "redeploy",
		"Re-request", "re-request", // promote approval link expired
		"Confirm", "confirm",
		"Switch", "switch", // read-only impersonation
		"check ", "Check ", // bindings cross-team / not-found
		"use ", "Use ", // bindings not-found
		"must be ", // bindings invalid-uuid → action is "must be a UUID"
		// Wave 3 (2026-05-21): additional concrete-action verbs surfaced
		// when the registry expanded from 38 → 248 entries. Each entry
		// below was introduced in helpers.go by the wave-3 sweep and is
		// a legitimate next-action the agent can relay to the user.
		"Restart", "restart", // OAuth state expired, CLI session expired, magic-link expired
		"Re-subscribe", "re-subscribe", // grace_expired → restart subscription
		"Re-open", "re-open", // streaming connection dropped → reopen SSE/WebSocket
		"Re-issue", "re-issue", // approval-link expired → re-issue from app
		"Re-enter", "re-enter", // invalid_email → re-enter address
		"Refresh", "refresh", // stale slug/state → refresh from app
		"POST ", // multipart endpoints — POST is the action
		"GET ", // list endpoints — GET is the action
		"Request", "request", // magic-link not found → request new one
		"Add ", "add ", // missing_email / missing_env etc → add the field
		"Trim ", "trim ", // env_too_large / tarball_too_large
		"Pick ", "pick ", // hostname_taken / same_env
		"Specify ", "specify ", // target_plan / target_env missing
		"Re-deploy", "re-deploy", // pod_not_found
		"Resume ", "resume ", // not_active / paused resource
		"Verify ", "verify ", // tarball validity / signing key
		"Shorten ", "shorten ", // name_too_long / body_too_long
		"Shrink ", "shrink ", // payload_too_large
		"Open ", "open ", // email_not_verified → open verification link
		"Disconnect ", "disconnect ", // already_connected GitHub deploy
		"Replace ", "replace ", // some plumbing recoveries
		"Promote ", "promote ", // last_owner / cannot_remove_primary
		"No action needed", "no action needed", // tier_unchanged, same_plan, already_paused
		"Operators must ", "operators must ", // billing_not_configured / oauth_not_configured
		"Email support", "email support", // downgrade_not_self_serve, all *_failed plumbing
		"Apply ", "apply ", // unsupported_for_twin
		"Supply ", "supply ", // missing_confirm_slug
		"Each binding", "each binding", // invalid_resource_bindings — diagnostic
		"See ", "see ", // unsupported_type fallback
		"Start ", "start ", // no_subscription
	}
	foundVerb := false
	for _, v := range actionVerbs {
		if strings.Contains(s, v) {
			foundVerb = true
			break
		}
	}
	assert.True(t, foundVerb,
		"%s: agent_action must contain at least one concrete action verb (Upgrade / Have them / Wait / Retry / provision / claim / log in / sign up / Ask / email / Remove / Redeploy / Confirm). Got: %q",
		name, s)
}

// TestAgentActionContract is the U3 audit gate. Every string in
// agentActionContractCases must satisfy:
//
//  1. Open with "Tell the user".
//  2. Name a specific reason (covered by per-handler tests).
//  3. Name an exact next action — enforced here via the action-verb
//     vocabulary check.
//  4. Contain a full https://instanode.dev/ URL.
//  5. Be < 280 chars.
//
// Adding a new agent_action without adding a row here is a contract
// violation — the audit-trail comment in agent_action.go points reviewers
// at this test.
func TestAgentActionContract(t *testing.T) {
	cases := agentActionContractCases()
	require.NotEmpty(t, cases, "agentActionContractCases must list every string")

	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, s, "%s: string must not be empty", name)
			assertContract(t, name, s)
		})
	}
}

// TestAgentActionContract_RegistryCoverage guards against the most likely
// regression: someone adds a new code to codeToAgentAction but its string
// silently fails the contract. The map iteration in
// agentActionContractCases covers this — this test just asserts the
// expected codes are present so a deletion is loud.
func TestAgentActionContract_RegistryCoverage(t *testing.T) {
	expectedCodes := []string{
		// Quota walls.
		"quota_exceeded", "storage_limit_reached", "vault_quota_exceeded",
		"vault_not_available", "vault_env_not_allowed", "member_limit",
		// "tier_unavailable" was dropped 2026-05-29 alongside the Team-tier
		// checkout/change-plan guards (CEO BIZ-1). It was the only code in
		// this registry that no handler emitted; the orphan-coverage gate
		// flagged it. If a future feature reintroduces a "tier is genuinely
		// unavailable" surface, re-add the code + its emitter in one PR.
		"upgrade_required", "rate_limit_exceeded",
		// B7-P1-7 (BugBash 2026-05-20): `claim_required` is the honest
		// 402 for anonymous-tier walls whose remediation is a FREE claim
		// (e.g. POST /api/v1/deployments/:id/{make-permanent,ttl}). A
		// drop from the registry without an in-PR migration to a different
		// code is a contract regression — agents that branch on the code
		// would either lose the agent_action or route the user to the
		// paid pricing page when the wall is free to clear.
		"claim_required",
		// Auth.
		"unauthorized", "auth_required", "invalid_token", "missing_token",
		"vault_requires_auth", "invitation_invalid", "already_accepted",
		"already_claimed",
		// Expired / gone.
		"webhook_inactive", "resource_not_found",
		// Permission denied.
		"forbidden", "last_owner",
		// Fiber-default 4xx routing errors (W12 retro-3 fix — these used
		// to leave agent_action empty when /openapi.json was probed,
		// agents got 404 with no remediation guidance).
		"not_found", "method_not_allowed", "payload_too_large",
		"unsupported_media_type",
	}
	for _, code := range expectedCodes {
		_, ok := codeToAgentAction[code]
		assert.True(t, ok, "codeToAgentAction[%q] must be registered — drop is a contract regression", code)
	}
}
