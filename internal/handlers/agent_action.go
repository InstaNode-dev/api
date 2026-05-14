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

import (
	"fmt"

	"instant.dev/internal/plans"
)

// ─────────────────────────────────────────────────────────────────────────────
// Multi-env / stack tier walls
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionMultiEnvUpgradeRequired is returned when a hobby/free team
// tries to use a multi-env workflow (stack family read, stack promote,
// vault copy, twin, family bulk-twin, pause/resume).
//
// W11 (2026-05-13) update: Hobby Plus ($19/mo) is the cheapest tier that
// unlocks multi-env (vault_envs_allowed: [development, staging, production]),
// so the upgrade copy points there rather than Pro — the agent surfaces
// the closer step to the user.
const AgentActionMultiEnvUpgradeRequired = "Tell the user multi-env workflows (staging/prod promote, env families, vault copy) need Hobby Plus or higher. Have them upgrade at https://instanode.dev/pricing — $19/mo, 30 seconds."

// ─────────────────────────────────────────────────────────────────────────────
// Resource pause/resume walls (POST /api/v1/resources/:id/pause | /resume)
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionPauseRequiresPro is returned when a hobby / anonymous / free team
// tries to pause a resource. Pause/resume is a Pro+ workflow because it shifts
// billing semantics (a paused row stops counting against the resource-count
// quota) — keeping it on the paid tier is consistent with the rest of the
// "stop billing the slot" surface.
const AgentActionPauseRequiresPro = "Tell the user pausing resources requires the Pro plan. Upgrade at https://instanode.dev/pricing — takes 30 seconds, then retry the pause."

// AgentActionResourceAlreadyPaused is returned by POST /resources/:id/pause
// when the row is already in 'paused' state. The remedy is "do nothing"
// (the resource is in the requested state) or call /resume to flip back —
// both of which the action verb covers via "Have them".
const AgentActionResourceAlreadyPaused = "Tell the user this resource is already paused. Have them call POST https://instanode.dev/api/v1/resources/:id/resume to bring it back online."

// AgentActionResourceNotPaused is returned by POST /resources/:id/resume when
// the row isn't in 'paused' state — typically because it's already active.
const AgentActionResourceNotPaused = "Tell the user this resource isn't paused, so there's nothing to resume. Have them check https://instanode.dev/app to see its current state."

// AgentActionStackPromoteMissingImageRef is returned when the source stack
// predates the image-ref persistence migration (no cached image to copy).
const AgentActionStackPromoteMissingImageRef = "Tell the user this stack predates the image-ref persistence migration, so promote has nothing to redeploy. Redeploy the source stack first at https://instanode.dev/app/stacks, then retry the promote."

// ─────────────────────────────────────────────────────────────────────────────
// Deploy tier walls
// ─────────────────────────────────────────────────────────────────────────────

// newAgentActionDeploymentLimitReached builds the 402 copy returned when a
// team hits its deployments_apps cap (plans.yaml). Names the tier and the
// exact cap, points the user at the next-tier upgrade URL.
//
// W11 (2026-05-13) routing: hobby's 1-deploy cap is solved by hobby_plus's
// 2-deploy cap ($19/mo) — the closer upgrade step. Pro is only the right
// nudge once the caller is already past the hobby_plus cap (or on a higher
// tier that ran into a higher cap, which today means growth → team).
func newAgentActionDeploymentLimitReached(tier string, limit int) string {
	switch plans.CanonicalTier(tier) {
	case "anonymous", "free", "hobby":
		return fmt.Sprintf(
			"Tell the user they've hit the %s tier deployment cap (%d app). Upgrade to Hobby Plus for 2 deployments at https://instanode.dev/pricing — $19/mo, 30 seconds.",
			tier, limit,
		)
	case "hobby_plus":
		return fmt.Sprintf(
			"Tell the user they've hit the %s tier deployment cap (%d apps). Upgrade to Pro for 10 deployments at https://instanode.dev/pricing — takes 30 seconds, no card for upgrade preview.",
			tier, limit,
		)
	default:
		return fmt.Sprintf(
			"Tell the user they've hit the %s tier deployment cap (%d apps). Upgrade to Pro for 10 deployments at https://instanode.dev/pricing — takes 30 seconds, no card for upgrade preview.",
			tier, limit,
		)
	}
}

// newAgentActionDeployAutoExpire24h is the headline copy attached to every
// new auto_24h-TTL deploy. Tells the LLM agent the three explicit routes to
// keep the deploy permanent so it can relay them to the user.
//
// This is NOT a 4xx wall — it's the success-path agent_action embedded in the
// 202 response. The four-contract requirements still apply: imperative
// opening, specific reason ("auto-expires in 24h"), exact next actions
// (make-permanent endpoint, ttl endpoint, team settings), full https URL.
// The string is intentionally longer than the 280-char tweet ceiling because
// it has to name THREE next actions; this is the canonical exception to
// the soft target documented at the top of this file.
func newAgentActionDeployAutoExpire24h(deployID, expiresAt string) string {
	return fmt.Sprintf(
		"Tell the user this deployment auto-expires in 24h (at %s UTC). Three ways to keep it: (1) call POST https://api.instanode.dev/api/v1/deployments/%s/make-permanent to keep it forever, (2) call POST https://api.instanode.dev/api/v1/deployments/%s/ttl {\"hours\":<1..8760>} for a custom TTL, or (3) flip the team default to permanent via PATCH https://api.instanode.dev/api/v1/team/settings {\"default_deployment_ttl_policy\":\"permanent\"} so future deploys never auto-expire. Six reminder emails will fire over the final 12h.",
		expiresAt, deployID, deployID,
	)
}

// AgentActionDeployMakePermanentAnonymous is returned when an anonymous tier
// caller tries to call POST /deployments/:id/make-permanent. Anonymous deploys
// are forced to 24h TTL and can't be kept; the only escape is to claim.
const AgentActionDeployMakePermanentAnonymous = "Tell the user anonymous deploys cannot be made permanent — they always expire in 24h. Claim the account at https://instanode.dev/start to keep deploys, then redeploy and call make-permanent."

// AgentActionDeployTTLHoursOutOfRange is returned when POST
// /deployments/:id/ttl receives an hours value outside 1..8760.
const AgentActionDeployTTLHoursOutOfRange = "Tell the user the TTL hours must be between 1 and 8760 (1 hour to 1 year). Have them retry with a valid number — see https://instanode.dev/docs/deploy-ttl."

// AgentActionTeamSettingsInvalidTTLPolicy is returned when PATCH
// /api/v1/team/settings receives an invalid default_deployment_ttl_policy.
const AgentActionTeamSettingsInvalidTTLPolicy = "Tell the user the default_deployment_ttl_policy must be 'auto_24h' or 'permanent'. Have them retry the PATCH with one of those values — see https://instanode.dev/docs/team-settings."

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

// AgentActionPromotionAlreadyUsed is returned in the 200 + ok:false body when
// an admin-issued single-use promo code is presented at /promotion/validate
// but its used_at column is already non-null. The wall is distinct from
// AgentActionPromotionInvalid because the remedy is different — "try a
// different code" is wrong advice when the code itself was valid but already
// redeemed (typically by another teammate). The sentence names the specific
// reason ("already redeemed by someone on this team") and the exact next
// action ("ask the admin who issued it for a new one") with the full URL.
const AgentActionPromotionAlreadyUsed = "Tell the user this promo code has already been redeemed by someone on this team. Ask the admin who issued it for a new one at https://instanode.dev/billing."

// AgentActionPromotionExpired is returned when an admin-issued promo code's
// expires_at is in the past. The plans-yaml path's "expired" branch shares
// the AgentActionPromotionInvalid copy via classifyPromotionError, but for
// admin codes we want a distinct "this code has expired, ask for a fresh
// one" sentence because the remedy is different from "try another code."
const AgentActionPromotionExpired = "Tell the user this promo code has expired. Ask the admin who issued it for a fresh code at https://instanode.dev/billing — admin codes have a fixed validity window."

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

// ─────────────────────────────────────────────────────────────────────────────
// Admin / customer-management surface (Track A)
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionAdminRequired is returned on every 403 from RequireAdmin —
// the /api/v1/admin/* customer-management endpoints (list, detail, tier
// change, promo issuance) gate on the JWT email matching ADMIN_EMAILS.
// Closed by default: an unset/empty ADMIN_EMAILS rejects every caller, so
// this sentence covers both "not on the allowlist" and "operator forgot
// to configure ADMIN_EMAILS" in one piece of advice.
//
// Kept in sync with the verbatim string used by middleware.RequireAdmin —
// the middleware can't import handlers (cycle), so both sides keep their
// own copy. The contract test asserts only one of the two copies; touching
// either without the other is the regression we want CI to catch.
const AgentActionAdminRequired = "Tell the user this endpoint requires platform-admin access. Ask support@instanode.dev via https://instanode.dev/support if you think this is wrong."

// newAgentActionAdminTierChanged is returned in the success response of
// POST /api/v1/admin/customers/:team_id/tier so the calling agent has
// verbatim copy to show the admin user — naming the team, the new tier,
// and the next action ("verify the bump on the team page"). The dashboard
// is the source of truth for "did the promote take?" so the agent_action
// points there.
func newAgentActionAdminTierChanged(teamID, newTier string) string {
	return fmt.Sprintf(
		"Tell the user team %s is now on the %s tier. Have them verify the bump at https://instanode.dev/app/team — existing resources were elevated immediately.",
		teamID, newTier,
	)
}

// newAgentActionAdminPromoIssued is returned in the success response of
// POST /api/v1/admin/customers/:team_id/promo so the agent has a verbatim
// sentence to relay to the admin user. Names the team, the code, and the
// next action ("share with the customer"). Code is short (8 chars) so the
// 280-char budget is never tight.
func newAgentActionAdminPromoIssued(teamID, code string) string {
	return fmt.Sprintf(
		"Tell the user a promo code %s was issued for team %s. Have them share it with the customer — redemption tracked at https://instanode.dev/app/admin.",
		code, teamID,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Promote-approval walls (non-dev target envs)
// ─────────────────────────────────────────────────────────────────────────────

func newAgentActionPromoteApprovalSent(toEnv, recipientEmail string) string {
	if recipientEmail == "" {
		recipientEmail = "the team owner's email"
	}
	return fmt.Sprintf(
		"Tell the user the promote to %s requires email approval. Check %s for a link expiring in 24h. Dev-env promotes skip this step. Track at https://instanode.dev/app/promotions.",
		toEnv, recipientEmail,
	)
}

// AgentActionPromoteTokenExpired — GET /approve/:token returns this when the row's status is 'expired'.
const AgentActionPromoteTokenExpired = "Tell the user the approval link expired. Re-request the promote at https://instanode.dev/app — links are valid for 24h."

// AgentActionReadOnlySession — RequireWritable middleware returns this on 403 when JWT has read_only:true.
const AgentActionReadOnlySession = "Tell the user this is a read-only impersonated session. Mutations are disabled. Switch back to your real account at https://instanode.dev/app to make changes."

// ─────────────────────────────────────────────────────────────────────────────
// Backup / restore walls (migration 031)
// ─────────────────────────────────────────────────────────────────────────────

// AgentActionBackupRequiresClaim is returned when an anonymous (unclaimed)
// caller hits POST /api/v1/resources/:id/backup. Backups are a registered-
// account feature — there is no claim-free path. Names the gated feature
// and the full claim URL.
const AgentActionBackupRequiresClaim = "Tell the user backups require a claimed account. Have them claim their resources at https://instanode.dev/app/claim — takes 30 seconds, no card."

// newAgentActionBackupRateLimited builds the 429 copy returned when a team
// exceeds its manual_backups_per_day cap. Names the tier, the cap, and
// points hobby callers at the Pro upgrade (where the cap is 100/day).
func newAgentActionBackupRateLimited(tier string, perDay int) string {
	return fmt.Sprintf(
		"Tell the user they've hit the %s tier manual-backup cap (%d/day). Upgrade to Pro for 100/day at https://instanode.dev/pricing — Pro also includes self-serve restore.",
		tier, perDay,
	)
}

// AgentActionRestoreRequiresPro is returned when a free/anonymous team
// hits POST /api/v1/resources/:id/restore. Restore is the first paid
// upgrade hook past Hobby. We deliberately name PRO here (and the
// HobbyPlus copy below for Hobby-tier callers) rather than always
// nudging to Pro — see AgentActionRestoreRequiresHobbyPlus for the
// Hobby→Hobby Plus path.
const AgentActionRestoreRequiresPro = "Tell the user self-serve restore requires the Pro plan or higher. Have them upgrade at https://instanode.dev/pricing for 30-day retention + 1-click restore. Takes 30 seconds."

// AgentActionRestoreRequiresHobbyPlus is the FIX-H (#66/#Q48 B36) fix.
// Pre-fix the Hobby-tier restore wall returned the Pro-upgrade copy,
// which silently skip-tiered the customer past the cheapest restore-
// enabled plan ($19 Hobby Plus) and onto Pro ($49). For a Hobby
// customer the right ladder is:
//
//	Hobby ($9, no restore) → Hobby Plus ($19, RESTORE) → Pro ($49) → Team
//
// So the 402 copy returned to a Hobby-tier caller points to Hobby Plus,
// not Pro. Pro is still the right target for free/anonymous callers
// because Hobby Plus has no claim-free entry path — a free user must
// upgrade through Hobby first, at which point the next nudge naturally
// surfaces Hobby Plus.
const AgentActionRestoreRequiresHobbyPlus = "Tell the user self-serve restore unlocks at Hobby Plus ($19/mo). Have them upgrade at https://instanode.dev/pricing — Hobby Plus is the cheapest tier with one-click restore."

// AgentActionRestoreInflight is returned when a second POST /restore
// arrives while a prior restore for the same resource is still in
// status='pending' or 'running'. Letting both run would race
// pg_restore --clean against itself and corrupt the target DB.
// Names the conflicting operation and the action: wait for the prior
// restore to finish, or contact support if it's stuck.
const AgentActionRestoreInflight = "Tell the user a restore is already in progress for this resource. Have them wait — re-POST once GET /restores shows the prior row as 'ok' or 'failed' at https://instanode.dev/app. If it stays 'running' past 30 minutes, contact support."

// AgentActionRestoreDestructiveAckRequired is returned when an in-place
// restore (no target_resource_id) is requested without the explicit
// destructive_acknowledgment: true field in the body. In-place restore
// runs `pg_restore --clean --if-exists` which DROPs every table in the
// target DB — we refuse that without an explicit ack so an agent that
// "just wants a backup test" can't wipe a live customer DB.
const AgentActionRestoreDestructiveAckRequired = "Tell the user in-place restore is destructive: pg_restore --clean drops every table in the target DB. Have them re-send with destructive_acknowledgment: true OR pass target_resource_id to restore into a fresh DB. See https://instanode.dev/llms-full.txt."

// AgentActionRestoreTargetCrossTeam is returned when target_resource_id
// belongs to a different team. We surface this as 403 rather than 404
// when the resource_id is syntactically valid but cross-tenant — the
// caller already proved ownership of the SOURCE resource, so a generic
// 404 on the target would be misleading.
const AgentActionRestoreTargetCrossTeam = "Tell the user target_resource_id must belong to the same team as the source. Have them check the target resource id at https://instanode.dev/app — restoring into another team's database is not allowed."

// AgentActionBackupIntegrityFailed is returned when a restore-time
// SHA-256 verification fails: the recomputed digest of the S3 object
// does not match the stored sha256. Either the S3 object was corrupted
// in transit, the row's digest was tampered with, or we hit a rare
// storage-side bit-rot. None of these are recoverable by the agent —
// the only safe next step is operator escalation.
const AgentActionBackupIntegrityFailed = "Tell the user this backup's integrity check failed (SHA-256 mismatch). The backup is unsafe to replay — have them email enterprise@instanode.dev with the backup_id. Status at https://instanode.dev/status."

// AgentActionRestoreBackupNotReady is returned when POST /restore references
// a backup_id that exists but is not in status='ok' (still pending/running,
// or failed). The user must wait for the backup to finish (or pick a
// different one) before they can restore from it.
const AgentActionRestoreBackupNotReady = "Tell the user this backup is not ready to restore from yet. Have them check https://instanode.dev/app — pending/running backups need a few minutes, failed backups can never be restored."

// ─────────────────────────────────────────────────────────────────────────────
// Email-confirmed deletion walls (Wave FIX-I, migration 044)
// ─────────────────────────────────────────────────────────────────────────────
//
// Two-step destruction: the agent CAN initiate but cannot finalise. Every
// sentence below is written from the agent's POV so the LLM surfaces it
// verbatim to the human user without paraphrasing the contract.

// newAgentActionDeletionPendingConfirmation builds the 202 copy returned
// when DELETE /api/v1/deployments/:id (or /stacks/:slug) queues a
// pending_deletions row. maskedEmail is the masked recipient
// ("m***@example.com"); ttlMinutes is the link lifetime.
//
// CRITICAL CONTRACT: the agent CANNOT confirm on the user's behalf. Only
// the human, via the email link or by hitting POST .../confirm-deletion
// with the plaintext token they pasted in, can finalise. We say this
// out loud in the sentence so the LLM cannot hallucinate that it has a
// way to bypass the email step.
func newAgentActionDeletionPendingConfirmation(maskedEmail string, ttlMinutes int) string {
	if maskedEmail == "" {
		maskedEmail = "the team owner's email"
	}
	return fmt.Sprintf(
		"Tell the user to check their email at %s. The deletion link expires in %d minutes. To free the slot the user must click the link (or paste the token from the email and POST it back to the confirm-deletion endpoint). The agent CANNOT confirm on the user's behalf — only the human can. If the user changes their mind, they can cancel from https://instanode.dev/app before the window closes.",
		maskedEmail, ttlMinutes,
	)
}

// AgentActionDeletionAlreadyPending is returned when a second DELETE
// fires while a pending_deletions row is still in flight. We don't
// generate a fresh token — that would silently invalidate the
// already-sent email and confuse the user. Tell the LLM to point the
// user at the existing email.
const AgentActionDeletionAlreadyPending = "Tell the user a deletion email is already in flight for this resource. Have them check their inbox (and spam) — the link is still valid. To cancel and start fresh, open https://instanode.dev/app and click Cancel on the pending-deletion banner."

// AgentActionDeletionTokenExpiredOrUsed is returned when the
// confirm-deletion endpoint cannot find a pending row for the supplied
// token. We deliberately conflate "expired", "already used", and "never
// existed" to avoid leaking token validity to an attacker. The remedy
// is the same in every case: re-request via DELETE.
const AgentActionDeletionTokenExpiredOrUsed = "Tell the user the confirmation token is expired or already used. Have them call DELETE on the resource again to mint a fresh email — see the flow at https://instanode.dev/docs/api. The previous link is dead either way."

// AgentActionDeletionConfirmed is returned in the 200 success envelope
// from POST /confirm-deletion. The agent surfaces this to the user as
// the all-clear that the slot is free.
const AgentActionDeletionConfirmed = "Tell the user the deletion is confirmed and the resource is fully torn down. The slot on their plan is now free — their next provision call will succeed. Live state at https://instanode.dev/app."

// AgentActionDeletionCancelled is returned in the 200 success envelope
// from DELETE /confirm-deletion. The resource stayed active; the slot
// stays consumed.
const AgentActionDeletionCancelled = "Tell the user the pending deletion is cancelled. The resource stays active and the slot stays consumed. If they want to delete again, they have to start fresh with a new DELETE call — see https://instanode.dev/docs/api."

// AgentActionDeletionEmailDisabled is the fallback used when the team
// has no primary user email on file (extremely rare — claimed teams
// always have at least one user row by construction). The handler can
// either fall back to immediate destruction (back-compat for the
// anonymous/free path) or refuse with this agent_action. We refuse on
// paid tiers because silently bypassing the confirm step on the only
// teams where the protection matters is a worse failure mode.
const AgentActionDeletionEmailDisabled = "Tell the user no confirmation email could be sent because no verified email is on file for this team. Have them add an owner email at https://instanode.dev/app/team before retrying the deletion."
