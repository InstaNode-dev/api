package handlers

// agent_action.go — single source of truth for every `agent_action` string
// returned to the calling LLM agent on a 402/403/409/410/4xx wall.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE U3 CONTRACT
// ─────────────────────────────────────────────────────────────────────────────
//
// Every `agent_action` string returned by this service MUST satisfy these four
// requirements. They are enforced by TestAgentActionContract in
// agent_action_test.go and re-asserted at the handler level by the touch-points
// listed below.
//
//   1. IMPERATIVE OPENING.
//      Every string MUST begin with "Tell the user" — the LLM agent's job is
//      to re-articulate the sentence to the human in front of it. Starting
//      every string with the same imperative makes the contract trivial for
//      a downstream LLM to recognize as "verbatim copy I should reproduce."
//
//   2. SPECIFIC REJECTION REASON.
//      Every string MUST name the concrete reason the request was rejected:
//      the tier ("hobby"), the limit ("5/day"), the policy ("env_policy_denied"),
//      the resource ("staging twin"). Generic phrasing ("their plan does not
//      allow...") is forbidden — the LLM cannot expand "their plan" into
//      something useful without inventing details.
//
//   3. EXACT NEXT ACTION.
//      Every string MUST tell the user the precise action that clears the
//      wall: "Upgrade to Pro", "Claim the resource", "Provision a twin",
//      "Contact support". "Try again later" is not a valid action — that's
//      a transient infra failure that should NOT carry an agent_action at all
//      (those omit the field; see codeToAgentAction curation principles).
//
//   4. FULL HTTPS URL.
//      Every string MUST contain an absolute `https://instanode.dev/...` URL.
//      Plain "/pricing" or "the pricing page" forces the LLM to guess the
//      hostname. The full URL is reproduced verbatim → guaranteed-correct
//      link in the user's terminal.
//
// Plus the soft target:
//
//   5. UNDER 280 CHARS (the "tweet ceiling").
//      LLMs reliably reproduce sub-tweet copy verbatim. Longer strings get
//      summarized, paraphrased, or truncated. The test asserts < 280 chars
//      on every constant below.
//
// ─────────────────────────────────────────────────────────────────────────────
// HOW TO USE
// ─────────────────────────────────────────────────────────────────────────────
//
// 1. Static walls: add a new const to this file, give it a clear name
//    (AgentAction<Domain><Reason>), reference it from the handler.
// 2. Dynamic walls (tier/limit interpolation): add a builder function
//    (newAgentAction<Domain><Reason>(args...)) here. Builders MUST keep
//    the four-contract requirements after interpolation.
// 3. The codeToAgentAction registry in helpers.go is the fallback path for
//    handlers that pass only an error code — those defaults are also under
//    test.
//
// Adding a new agent_action string OUTSIDE this file (inline in a handler) is
// a contract violation. The audit runs `grep "agent_action" internal/handlers`
// on every PR — new strings must land in this file or extend codeToAgentAction.

import "fmt"

// ─────────────────────────────────────────────────────────────────────────────
// Multi-env / stack tier walls
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionMultiEnvUpgradeRequired is returned when a hobby/free team
// tries to use a multi-env workflow (stack family read, stack promote).
const AgentActionMultiEnvUpgradeRequired = "Tell the user multi-env workflows (staging/production promote, env families) require the Pro plan. Have them upgrade at https://instanode.dev/pricing — takes 30 seconds."

// AgentActionStackPromoteMissingImageRef is returned when the source stack
// predates the image-ref persistence migration (no cached image to copy).
const AgentActionStackPromoteMissingImageRef = "Tell the user this stack predates the image-ref persistence migration, so promote has nothing to redeploy. Redeploy the source stack first at https://instanode.dev/app/stacks, then retry the promote."

// ─────────────────────────────────────────────────────────────────────────────
// Deploy tier walls
// ─────────────────────────────────────────────────────────────────────────────

// newAgentActionDeploymentLimitReached builds the 402 copy returned when a
// team hits its deployments_apps cap (plans.yaml). Names the tier and the
// exact cap, points the user at the upgrade URL.
func newAgentActionDeploymentLimitReached(tier string, limit int) string {
	return fmt.Sprintf(
		"Tell the user they've hit the %s tier deployment cap (%d apps). Upgrade to Pro for 10 deployments at https://instanode.dev/pricing — takes 30 seconds, no card for upgrade preview.",
		tier, limit,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Private-deploy walls (Track A — migration 020)
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionPrivateDeployRequiresPro is returned when a hobby / anonymous /
// free team tries to set private=true on POST /deploy/new. Names the gated
// feature ("private deploys"), the required tier ("Pro"), and points at the
// exact upgrade URL — satisfying all four contract requirements.
const AgentActionPrivateDeployRequiresPro = "Tell the user private deploys require Pro tier. Upgrade at https://instanode.dev/pricing — takes 30 seconds."

// AgentActionPrivateDeployRequiresAllowedIPs is returned when a caller sets
// private=true but supplies no allowed_ips. We do NOT allow a "private deploy
// with zero allowed IPs" — that would silently make the app unreachable.
const AgentActionPrivateDeployRequiresAllowedIPs = "Tell the user a private deploy needs at least one allowed IP or CIDR. Have them pass allowed_ips like [\"1.2.3.4\",\"10.0.0.0/8\"] — see https://instanode.dev/docs/private-deploys."

// ─────────────────────────────────────────────────────────────────────────────
// Billing promotion walls (POST /api/v1/billing/promotion/validate)
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionPromotionInvalid is returned in the 200 + ok:false body when a
// promotion code is rejected (not found, wrong plan, expired, exhausted).
// The handler returns 200 (not 4xx) so the dashboard renders the red state
// through its normal success-path parser — but MCP / CLI agents still need
// LLM-ready copy to tell the user what to do next, which this constant
// supplies. Names the rejection reason and the fix ("try a different
// code") and contains the full https://instanode.dev/billing URL.
const AgentActionPromotionInvalid = "Tell the user this promo code isn't valid for the requested plan. Have them try a different code at https://instanode.dev/billing — promotion codes are case-insensitive."

// ─────────────────────────────────────────────────────────────────────────────
// Storage / vault tier walls (called from respondErrorWithAgentAction)
// ─────────────────────────────────────────────────────────────────────────────

// newAgentActionStorageLimitReached builds the 402 copy returned when a
// team hits the per-tier object-storage cap.
func newAgentActionStorageLimitReached(tier string, limitMB int) string {
	return fmt.Sprintf(
		"Tell the user they've hit the %s tier storage cap (%dMB). Upgrade to Pro for 5GB at https://instanode.dev/pricing to provision more storage.",
		tier, limitMB,
	)
}

// newAgentActionVaultQuotaExceeded builds the 402 copy returned when a team
// hits its vault-entry cap for the current plan.
func newAgentActionVaultQuotaExceeded(tier string, maxEntries int) string {
	return fmt.Sprintf(
		"Tell the user they've hit the %s tier vault cap (%d entries). Upgrade to Pro for more secrets at https://instanode.dev/pricing — takes 30 seconds.",
		tier, maxEntries,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Env-policy / role walls (403)
// ─────────────────────────────────────────────────────────────────────────────

// newAgentActionEnvPolicyDenied builds the 403 copy returned when a team's
// env_policy refuses an action because the caller's role isn't in the
// allowed set. Names the env, the action, the allowed roles, and the
// caller's actual role.
func newAgentActionEnvPolicyDenied(env, action, allowedRoles, callerRole string) string {
	if callerRole == "" {
		callerRole = "unknown"
	}
	return fmt.Sprintf(
		"Tell the user the %s env requires the %s role to %s. Their role is %s — have a team owner run the prompt at https://instanode.dev/app/team to adjust the policy or run the action.",
		env, allowedRoles, action, callerRole,
	)
}

// newAgentActionOwnerRequired builds the 403 copy returned when an action
// requires the owner role (e.g. PUT /team/env-policy).
func newAgentActionOwnerRequired(callerRole string) string {
	if callerRole == "" {
		callerRole = "unknown"
	}
	return fmt.Sprintf(
		"Tell the user updating the team's env-policy requires the owner role. Their role is %s — have the team owner run the prompt from https://instanode.dev/app/team instead.",
		callerRole,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Family-binding walls (resolveResourceBindings → mapBindingError)
// ─────────────────────────────────────────────────────────────────────────────

// newAgentActionBindingInvalidUUID is returned when resource_bindings[KEY]
// is neither a UUID nor a "family:<uuid>" reference.
func newAgentActionBindingInvalidUUID(envKey, rawValue string) string {
	return fmt.Sprintf(
		"Tell the user the deploy's resource_bindings.%s value must be a resource token UUID or family:<family_root_id>. They provided %q. See https://instanode.dev/docs/family-bindings.",
		envKey, rawValue,
	)
}

// AgentActionBindingFamilyDisabled is returned when family: prefix is used
// but the server has FAMILY_BINDINGS_ENABLED=false.
const AgentActionBindingFamilyDisabled = "Tell the user this server has family bindings disabled. Remove the family: prefix and pass a raw resource-token UUID instead — see https://instanode.dev/docs/family-bindings."

// newAgentActionBindingNotFound is returned when the referenced resource
// (raw or family root) doesn't exist.
func newAgentActionBindingNotFound(envKey string) string {
	return fmt.Sprintf(
		"Tell the user the resource referenced in resource_bindings.%s doesn't exist. Have them list their families with GET https://instanode.dev/api/v1/resources/families and use a valid root id.",
		envKey,
	)
}

// newAgentActionBindingCrossTeam is returned when the referenced resource
// belongs to a different team.
func newAgentActionBindingCrossTeam(envKey string) string {
	return fmt.Sprintf(
		"Tell the user the resource in resource_bindings.%s belongs to a different team. They can only reference resources owned by their own team — check the team picker at https://instanode.dev/app.",
		envKey,
	)
}

// newAgentActionBindingNoEnvTwin is returned when a family binding resolves
// to a family that has no member in the deploy's env (e.g. deploying to
// staging but only the production twin exists).
func newAgentActionBindingNoEnvTwin(rootID, resourceName, env string) string {
	name := resourceName
	if name == "" {
		name = rootID
	}
	return fmt.Sprintf(
		"Tell the user to provision a %s twin of %q first: POST https://instanode.dev/api/v1/resources/%s/provision-twin with {\"env\":\"%s\"}. The deploy targets env=%s but no family member exists there.",
		env, name, rootID, env, env,
	)
}

// AgentActionBindingLookupFailed is returned for transient lookup failures
// during binding resolution (503 path). Even though this is a transient
// error, the user-visible advice is "retry in a few seconds" which is a
// concrete action the LLM can pass on.
const AgentActionBindingLookupFailed = "Tell the user the platform couldn't resolve the resource binding right now. Retry the deploy in ~10 seconds — if it persists, check https://instanode.dev/status."
