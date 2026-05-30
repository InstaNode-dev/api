package handlers

import (
	"crypto/rand"
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"instant.dev/internal/circuit"
	"instant.dev/internal/middleware"
)

// randRead is a package-level indirection over crypto/rand.Read so coverage
// tests can force the (otherwise practically unreachable) rand.Read error arm
// of the secure-token generators (generateAppID, generateOAuthState,
// generateSessionID). It defaults to crypto/rand.Read; production behaviour is
// byte-for-byte identical.
var randRead = rand.Read

// init wires the Idempotency middleware's ErrResponseWritten check.
//
// BB2-D5 (2026-05-14): the middleware needs to recognise the sentinel
// respondError* returns so it can CACHE the 4xx response body it just
// wrote (e.g. 402 quota_exceeded) instead of bailing as if a plumbing
// error had aborted the request. We register via init() instead of a
// direct import in middleware because handlers already imports middleware
// (webhook.go, deploy.go, etc.) — a back-edge would deadlock the package
// graph at compile time. The Idempotency middleware's default is a
// no-op false-returner, so test packages that don't import handlers
// keep the pre-fix behaviour.
func init() {
	middleware.IsResponseWrittenErr = func(err error) bool {
		return errors.Is(err, ErrResponseWritten)
	}
}

// ErrResponseWritten is the sentinel respondError returns to signal "I
// already wrote the response body — propagate me up but DO NOT let Fiber's
// generic ErrorHandler overwrite the response."
//
// Callers that do `return ..., respondError(...)` from a helper get a
// non-nil error and short-circuit correctly even when the underlying
// c.Status().JSON() returned nil (the normal success case for body write).
//
// The router and test ErrorHandlers both detect this sentinel and return
// nil without writing — preserving the 400/403/etc. response respondError
// already committed. See router/router.go and testhelpers/testhelpers.go.
var ErrResponseWritten = errors.New("response already written by respondError")

// DefaultPricingURL is the URL agents should follow to clear a quota wall.
// Plumbed as a package-level var so tests and self-hosted operators can
// override it (e.g. point at a custom billing portal). Mirrors
// middleware.QuotaUpgradeURL — kept here to avoid an import cycle and to
// give respondError its own knob.
var DefaultPricingURL = "https://instanode.dev/pricing"

// DefaultLoginURL is the URL agents should show users when their session
// token is rejected.
var DefaultLoginURL = "https://instanode.dev/login"

// errorCodeMeta is the auto-populated agent-facing metadata for a known
// error code. The map below pairs short, machine-stable codes (e.g.
// "invalid_token", "storage_limit_reached") with a sentence the agent can
// surface verbatim to the human user, plus — for codes that always benefit
// from one — a default UpgradeURL.
//
// Call sites that need a tier-aware override (e.g. "you've hit the *hobby*
// limit") should call respondErrorWithAgentAction directly instead of
// relying on the default.
type errorCodeMeta struct {
	AgentAction string
	UpgradeURL  string
}

// AgentActionContactSupport is the fallback agent_action sentence returned on
// 5xx codes that don't have a domain-specific entry in codeToAgentAction.
// Names the support email, the concrete next action ("email with this
// request_id"), and contains the full https://instanode.dev URL — satisfies
// every clause of the U3 contract (see agent_action.go).
//
// Used by respondError when status >= 500 and the code is not in the
// registry. Keeps the agent_action field populated even for plumbing
// errors so the calling agent always has something concrete to relay.
const AgentActionContactSupport = "Tell the user something on our side went wrong. Email support@instanode.dev with this request_id and a brief description — see https://instanode.dev/support."

// codeToAgentAction maps respondError `code` values to the sentence the
// agent should surface and, where relevant, the upgrade URL. Codes absent
// from this map produce a response with no agent_action field (which is
// omitempty so existing clients see no change).
//
// Curation principles:
//   - Quota / tier-gate errors get an upgrade_url.
//   - Auth-token errors point at login.
//   - "Expired" / "not_found" tell the agent to re-provision.
//   - Pure plumbing errors (db_error, list_failed, stream_failed,
//     provision_failed) are deliberately omitted from this static map —
//     respondError falls back to AgentActionContactSupport for any 5xx
//     code that doesn't have an entry here.
var codeToAgentAction = map[string]errorCodeMeta{
	// ── Quota walls ────────────────────────────────────────────────────────
	// Each string adheres to the U3 contract (see agent_action.go): opens
	// with "Tell the user", names the specific reason, names the exact next
	// action, contains a full https://instanode.dev/ URL, under 280 chars.
	"quota_exceeded": {
		AgentAction: "Tell the user they've hit their plan's usage limit. Upgrade to Pro at https://instanode.dev/pricing — takes 30 seconds and unlocks higher quotas.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"storage_limit_reached": {
		AgentAction: "Tell the user they've hit their plan's storage limit. Upgrade to Pro for 5GB at https://instanode.dev/pricing to provision more storage.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_quota_exceeded": {
		AgentAction: "Tell the user they've hit their plan's vault entry quota. Upgrade to Pro at https://instanode.dev/pricing to add more secrets.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_not_available": {
		AgentAction: "Tell the user the vault feature isn't available on their current plan. Upgrade to Hobby or higher at https://instanode.dev/pricing to use it.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_env_not_allowed": {
		AgentAction: "Tell the user their plan only allows the default vault env; multi-env vault requires Pro. Upgrade at https://instanode.dev/pricing — takes 30 seconds.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"member_limit": {
		AgentAction: "Tell the user they've hit the team member limit for their plan. Upgrade to Pro at https://instanode.dev/pricing to add more teammates.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"upgrade_required": {
		AgentAction: "Tell the user this feature requires the Pro plan or higher. Upgrade at https://instanode.dev/pricing — takes 30 seconds.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	// "tier_unavailable" was removed 2026-05-29 along with the Team-tier
	// checkout/change-plan guards (CEO BIZ-1). The only emitters of this
	// code lived in those two billing branches; with both gone, the
	// codeToAgentAction entry was orphan-flagged by
	// TestCodeToAgentAction_NoOrphans. If a future feature reintroduces
	// a "tier is genuinely unavailable" surface, re-add the entry here
	// and emit it from the new site in the same PR.
	"events_query_failed": {
		AgentAction: "Tell the user the deployment-events read is temporarily unavailable. Retry in 30 seconds; the deploy itself isn't affected.",
		UpgradeURL:  "",
	},
	"rate_limit_exceeded": {
		AgentAction: "Tell the user they've sent too many requests in a short window. Wait 60 seconds and retry — or upgrade to Pro at https://instanode.dev/pricing for higher limits.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},

	// ── Auth / token errors ────────────────────────────────────────────────
	"unauthorized": {
		AgentAction: "Tell the user their INSTANODE_TOKEN is missing or invalid. Have them log in at https://instanode.dev/login to mint a new one — takes 30 seconds.",
	},
	// brevo_secret_mismatch is a Brevo webhook URL-path-token mismatch — NOT a
	// user-auth failure. The generic "unauthorized" agent_action ("log in to mint
	// a new INSTANODE_TOKEN") sent an unrelated recovery script that was
	// uselessly wrong for the actual incident (operator must verify their Brevo
	// dashboard webhook URL contains the configured BREVO_WEBHOOK_SECRET).
	// API-6 (QA 2026-05-29): give this error its own copy. Follows the U3
	// contract — "Tell the user" opening, https://instanode.dev/ URL, < 280 chars.
	// BUG-API-021 (QA 2026-05-29): the pre-fix agent_action literally
	// named the BREVO_WEBHOOK_SECRET env var, which (a) is informational
	// disclosure to a brute-forcer probing the public 401 surface — they
	// learn the exact env-var name the operator must rotate — and (b)
	// targets the operator using internal vocab the calling agent has no
	// business surfacing to the end-user. The new copy drops the env-var
	// name and points at the public docs page (which documents the
	// rotation procedure for an operator that follows the link). Wire
	// contract preserved: error code, status, message all unchanged —
	// only the agent_action sentence is softened.
	"brevo_secret_mismatch": {
		AgentAction: "Tell the user this is a Brevo-webhook configuration mismatch, not their auth — they have no action. Operators: rotate the Brevo webhook secret and update the api Deployment — see https://instanode.dev/docs/email.",
	},
	// webhook_secret_mismatch is the generic per-provider webhook URL-path-token
	// or shared-secret mismatch surface. API-19/96/97/98 (QA 2026-05-29): the
	// pre-fix path returned generic 401 envelopes for /api/v1/email/webhook/brevo
	// and /api/v1/email/webhook/ses unauth POSTs, which sent the canonical
	// "log in for new INSTANODE_TOKEN" agent_action to operators chasing a
	// webhook-config incident. Same shape as brevo_secret_mismatch but
	// distinguishes the secret-not-configured branch from the signature-mismatch
	// branch below. Operator must wire the corresponding env var
	// (BREVO_WEBHOOK_SECRET / SES_SNS_SUBSCRIPTION_ARN) before the route accepts.
	// BUG-API-021 sibling: "set the corresponding webhook secret env var"
	// pointed at an internal env-var by name. Same softening as
	// brevo_secret_mismatch above — drop env-var vocab from the public
	// 401 surface; the docs page covers operator-side wiring.
	"webhook_secret_mismatch": {
		AgentAction: "Tell the user this is an email-webhook configuration mismatch, not their auth — they have no action. Operators: configure the webhook secret in the api Deployment — see https://instanode.dev/docs/email.",
	},
	// webhook_signature_mismatch is the per-provider signature-verification
	// failure surface — the secret IS configured, the inbound payload's HMAC /
	// SNS signature did NOT verify against the body. Distinct from
	// webhook_secret_mismatch so observability can split "we haven't deployed
	// the secret yet" from "someone is sending bad signatures (or the provider
	// rotated keys)" without an operator hand-grepping log lines. Used by
	// /api/v1/email/webhook/brevo + /api/v1/email/webhook/ses.
	// BUG-API-021 sibling: "the api Deployment's env var" leaked the
	// internal wiring; soften to "the configured webhook secret" so the
	// 401 stays self-explanatory without naming env-var keys.
	"webhook_signature_mismatch": {
		AgentAction: "Tell the user the inbound email-webhook signature did not verify. Operators: confirm the dashboard webhook secret matches the configured value and the provider hasn't rotated signing keys — see https://instanode.dev/docs/email.",
	},
	// webhook_method_not_allowed surfaces the GET-on-a-POST-only webhook URL
	// path (BUG-API-098). Brevo's dashboard sometimes sends a GET pre-flight to
	// the configured webhook URL; the pre-fix path returned generic 401 which
	// could make the dashboard abandon the config. 405 with this code surfaces
	// the actual situation (the URL exists, but only accepts POST).
	"webhook_method_not_allowed": {
		AgentAction: "Tell the user this webhook URL only accepts POST. Provider dashboards confirming a webhook URL via GET should treat 405 as 'URL exists' — see https://instanode.dev/docs/email.",
	},
	// internal_token_required is the worker-to-api auth-failure surface for
	// the /internal/* routes (terminate, resend-magic-link, backup-quota refund).
	// API-26/27/28/77/78 (QA 2026-05-29): pre-fix these handlers parsed the
	// path :id / request body BEFORE checking the secret, so a bogus token
	// with a malformed path returned 400 invalid_team_id / 400 invalid_body
	// instead of 401 — inverting the fail-closed posture (a probe could
	// distinguish "secret unset" from "secret wrong" by the 400/401 envelope).
	// Post-fix: the auth check runs first; any missing / malformed worker
	// JWT returns 401 internal_token_required, surfacing the actual fault to
	// operators without leaking shape information about the path or body to
	// unauthenticated probes.
	"internal_token_required": {
		AgentAction: "Tell the user this is an internal worker-to-api route. The caller must present a valid worker JWT signed with WORKER_INTERNAL_JWT_SECRET — see https://instanode.dev/docs/internal.",
	},
	// invalid_message is the SES/SNS-inner-Message-not-JSON arm. Distinct
	// from invalid_payload (the envelope parse) so a debugging operator can
	// tell "AWS gave us a malformed envelope" from "AWS gave us a malformed
	// inner Message" without re-reading the response message string.
	"invalid_message": {
		AgentAction: "Tell the user the inner Message field of the SES/SNS envelope could not be parsed as JSON. Provider-side bug; operators must inspect the raw payload in audit — see https://instanode.dev/docs/email.",
	},
	"auth_required": {
		AgentAction: "Tell the user this action requires an authenticated session. Have them log in or sign up at https://instanode.dev/login — both flows mint a token.",
	},
	// BUG-API-020 (QA 2026-05-29): the `invalid_token` code is emitted from
	// 9 handler sites — webhook receiver path token (webhook.go:528/811),
	// invitation token (teams.go:170/248), storage URL path token
	// (storage_presign.go:114), onboarding claim JWT (onboarding.go:92/282/294),
	// stack manifest needs token (stack.go:539), deploy logs URL path token
	// (logs.go:148). None of them are an INSTANODE_TOKEN. The pre-fix
	// agent_action sent agents on the wrong remediation path ("have the user
	// log in") for every one of those surfaces. The new copy stays neutral —
	// the token in the URL path or claim JWT — and points at the docs page
	// covering both shapes. The auth/Bearer 401 path is unaffected (it lives
	// at middleware/auth.go:61 in `unauthorizedAgentAction`, which still
	// names INSTANODE_TOKEN because there the wording is correct).
	"invalid_token": {
		AgentAction: "Tell the user the supplied token is invalid or expired. URL path tokens must be a valid UUID returned by a provision response (POST /db/new, /webhook/new, /storage/new etc.); onboarding claim JWTs come from anonymous provision flows — see https://instanode.dev/docs.",
	},
	"missing_token": {
		AgentAction: "Tell the user no INSTANODE_TOKEN was provided. Have them log in at https://instanode.dev/login and pass it via Authorization: Bearer <token>.",
	},
	// cookie_missing_or_expired — POST /auth/exchange (browser-only bridge
	// from the magic-link / OAuth callback into the SPA) saw no bridge
	// cookie. The 30-second transient window closed or the cookie was
	// dropped. The remediation is to restart the sign-in flow.
	"cookie_missing_or_expired": {
		AgentAction: "Tell the user the sign-in handoff window expired. Have them start the login flow again at https://instanode.dev/login — the bridge cookie lives for 30 seconds.",
	},
	"vault_requires_auth": {
		AgentAction: "Tell the user vault access requires an authenticated session. Have them log in at https://instanode.dev/login to mint a token.",
	},
	"invitation_invalid": {
		AgentAction: "Tell the user this invitation link is invalid or already used. Ask the team owner to send a fresh invitation from https://instanode.dev/app/team.",
	},
	"already_accepted": {
		AgentAction: "Tell the user this invitation has already been accepted — they're on the team. Have them open https://instanode.dev/app to see their resources.",
	},
	"already_claimed": {
		AgentAction: "Tell the user these resources were already claimed by another account. If they believe this is wrong, have them email support@instanode.dev — see https://instanode.dev/support.",
	},

	// ── Expired / gone ─────────────────────────────────────────────────────
	"webhook_inactive": {
		AgentAction: "Tell the user this webhook token has expired or been deactivated. Have them provision a fresh one with POST https://instanode.dev/webhook/new.",
	},
	// BUG-API-423 (QA 2026-05-29): /webhook/receive/:token's 404 used to
	// emit the generic `not_found` code which agents grepping for the
	// specific surface couldn't disambiguate from any other route 404.
	// `webhook_not_found` makes the surface explicit so a webhook sender
	// can distinguish "I have the wrong URL" from "I'm hitting a
	// completely unrelated 404". Same wire shape (400/404 status,
	// message body unchanged) — only the code keyword is sharper.
	"webhook_not_found": {
		AgentAction: "Tell the user this webhook token does not exist. Confirm the URL path token is the one returned by POST https://instanode.dev/webhook/new — anon resources also auto-expire after 24h.",
	},
	"resource_not_found": {
		AgentAction: "Tell the user this resource no longer exists — anonymous resources auto-expire after 24h. Have them provision a fresh one at https://instanode.dev/docs/quickstart.",
	},

	// ── Permission denied ──────────────────────────────────────────────────
	"forbidden": {
		AgentAction: "Tell the user they don't have permission for this action. Have them confirm they're logged in to the right team at https://instanode.dev/app/team.",
	},
	"last_owner": {
		AgentAction: "Tell the user the team needs at least one owner. Have them promote another member to owner at https://instanode.dev/app/team before changing or removing this one.",
	},
	"cannot_remove_primary": {
		AgentAction: "Tell the user they can't remove the primary user — every team needs a primary. Have them promote another member first via POST https://instanode.dev/api/v1/team/members/<other_user_id>/promote-to-primary, then retry the removal.",
	},
	"cannot_assign_owner_role": {
		AgentAction: "Tell the user the owner role can't be assigned via PATCH role — ownership transfers atomically. Have them call POST https://instanode.dev/api/v1/team/members/<user_id>/promote-to-primary instead.",
	},

	// ── Body-validation errors ─────────────────────────────────────────────
	// T19 P1-3 (BugHunt 2026-05-20): `invalid_body` was the one
	// request-fix 4xx without an agent_action — every other 4xx
	// (name_required, invalid_name, missing_token, ...) had one. The
	// `ErrorResponse` schema description promises agent_action on
	// "request-fix errors"; matching that contract here.
	"invalid_body": {
		AgentAction: "Tell the user the request body is not valid JSON. Have them check for trailing commas, unquoted keys, and the matching Content-Type header — see https://instanode.dev/docs.",
	},
	// B4-F7 (BugBash 2026-05-20): invalid_email landed in respondError
	// without an agent_action — the W7G "every 4xx carries the LLM-ready
	// next sentence" contract was silently violated on the magic-link
	// start path. Sentence names the reason (bad-syntax email) and the
	// concrete remedy (have the user re-enter a valid address); full URL.
	"invalid_email": {
		AgentAction: "Tell the user the email address looks malformed. Have them re-enter a syntactically valid address (e.g. you@example.com) and retry the magic-link sign-in at https://instanode.dev/login.",
	},
	"invalid_email_format": {
		AgentAction: "Tell the user the email address fails RFC 5322 validation. Have them re-enter a syntactically valid address (e.g. you@example.com) and retry — see https://instanode.dev/docs.",
	},

	// ── Provisioning 429 quota walls ───────────────────────────────────────
	// B10-P1-3 / B13-F6 (BugBash 2026-05-20): the 429
	// `provision_limit_reached` envelope was missing agent_action +
	// upgrade_url despite being the most-hit programmatic wall. Agents
	// branching on `error` saw the code but had no LLM-ready sentence to
	// relay; CLAUDE.md convention #6 + the W7G contract both promise one.
	// The sentence names the daily-cap reason and the exact next action
	// (claim to keep using the same resources, or sign in).
	"provision_limit_reached": {
		AgentAction: "Tell the user they've hit the anonymous daily provisioning cap for this network. Have them claim their existing resources at https://instanode.dev/claim — takes 30 seconds, lifts the cap, and keeps every existing token usable.",
		UpgradeURL:  "https://instanode.dev/claim",
	},

	// ── Fiber-default 4xx routing errors ───────────────────────────────────
	// The default Fiber 404/405/413/415 paths flow through the ErrorHandler
	// in router.go which calls handlers.WriteFiberError -> respondError.
	// Pre-W12 the resulting envelope had `message` and `request_id`
	// populated but agent_action was empty — agents probing a stale or
	// wrong URL got no guidance on what to do next. Each sentence below
	// follows the §10.15 contract: opens with "Tell the user", names the
	// concrete failure, points at the agent's next action (verify the URL
	// via the docs, fix the method, shrink the payload, set Content-Type).
	// Codes match the keywords WriteFiberError emits for Fiber's
	// StatusNotFound / StatusMethodNotAllowed / StatusRequestEntityTooLarge
	// / StatusUnsupportedMediaType.
	"not_found": {
		// BUG-API-105 (QA 2026-05-29): the agent_action used to tack on
		// "anon resources also auto-expire after 24h" — irrelevant when
		// the 404 is a typo'd internal path or unknown route, and
		// actively misleading on authenticated misroutes. Hint kept
		// behind a "see /docs" pointer; the auto-expire footnote now
		// only fires when the surface-specific 404 (resource_not_found
		// / webhook_not_found / etc.) emits it.
		AgentAction: "Tell the user the URL is wrong or the resource no longer exists. Have them check the path against https://instanode.dev/docs — if they were calling a token-keyed URL the token may have expired or been mistyped.",
	},
	"method_not_allowed": {
		AgentAction: "Tell the user the HTTP method is wrong for this URL. Have them check the Allow response header (or https://instanode.dev/docs) for the supported methods.",
	},
	"payload_too_large": {
		AgentAction: "Tell the user the request body is too big. Have them shrink it — see per-endpoint limits at https://instanode.dev/docs.",
	},
	"unsupported_media_type": {
		AgentAction: "Tell the user the Content-Type is wrong. Have them use application/json for JSON routes or multipart/form-data for /deploy/new and /stacks/new — see https://instanode.dev/docs.",
	},

	// ── Circuit-breaker shorts ─────────────────────────────────────────────
	// Returned when an upstream dependency (provisioner gRPC, Razorpay HTTP,
	// Redis backing DPoP replay-protection) has been failing fast enough
	// that the breaker opened and we're refusing calls outright. agent_action
	// sentences point at the status page so the agent surfaces real-time
	// recovery info (not a static "try again later").
	"provisioner_unavailable": {
		AgentAction: "Tell the user the provisioner is temporarily unavailable. Retry in 30 seconds — see live status at https://instanode.dev/status.",
		UpgradeURL:  "https://instanode.dev/status",
	},

	// MR-P0-3 (BugBash 2026-05-20): explicit agent_action for the catch-all
	// `provision_failed` 503 — historically omitted here so the response fell
	// back to AgentActionContactSupport ("email support"). For an atomic-
	// persistence-failure landing this code, that fallback is wrong: the
	// backend object was just torn down (best-effort) and the row soft-
	// deleted, so the right action is "retry the provision with backoff,"
	// NOT "email support." Sentence keeps the U3 contract (opens with
	// "Tell the user", names the reason, names the action, full
	// https://instanode.dev URL, < 280 chars). The retry_after_seconds
	// header on a 503 also signals the backoff window.
	"provision_failed": {
		AgentAction: "Tell the user provisioning hit a transient platform-persistence error and no charge or resource was created. Retry the same request with exponential backoff (start at 5s, cap at 60s) — see https://instanode.dev/status if it persists.",
	},
	"billing_provider_unavailable": {
		AgentAction: "Tell the user the billing provider is temporarily unavailable. Retry the upgrade in 60 seconds — see status at https://instanode.dev/status.",
		UpgradeURL:  "https://instanode.dev/status",
	},
	"dpop_replay_check_unavailable": {
		AgentAction: "Tell the user the replay-protection store is temporarily degraded. Retry in 30 seconds — token is valid; see https://instanode.dev/status for live recovery info.",
		UpgradeURL:  "https://instanode.dev/status",
	},

	// ── Email-confirmed deletion (Wave FIX-I, migration 044) ──────────────
	// Generic fallback when respondError is called with these codes and no
	// per-call agent_action override is supplied. The deploy/stack handlers
	// always pass a templated sentence via respondErrorWithAgentAction
	// (because the masked email + ttl are dynamic), but a 410-from-cron or
	// a worker calling the codepath without context lands here.
	"deletion_token_invalid": {
		AgentAction: AgentActionDeletionTokenExpiredOrUsed,
	},
	"deletion_already_pending": {
		AgentAction: AgentActionDeletionAlreadyPending,
	},
	"deletion_email_disabled": {
		AgentAction: AgentActionDeletionEmailDisabled,
	},

	// ── Wave 3 consolidated (2026-05-21): exhaustive agent_action coverage ──
	//
	// Pre-wave3 the registry covered ~38 codes. An AST walk of every
	// respondError* call site (rg -oE 'respondError[a-zA-Z]*\([^,]+,...,
	// "<code>"' internal/handlers/) surfaced 227 unique emitted codes;
	// the registry-iterating coverage test
	// (TestErrorCode_HasAgentAction) walks the same set and asserts every
	// emitted code has either an entry here OR is in an explicit
	// allowlist of pure plumbing codes that legitimately fall back to
	// AgentActionContactSupport on 5xx (no domain-specific guidance
	// would be more useful than "email support").
	//
	// Each entry below names the concrete failure, names the agent's next
	// action, includes a full https://instanode.dev/ URL, and stays under
	// 280 chars per the U3 contract (see agent_action.go).

	// ── Validation 4xx: missing required fields ────────────────────────────
	"missing_name": {
		AgentAction: "Tell the user a 'name' field is required for this operation. Add a short human label (1-64 chars; letters, numbers, spaces, dashes) and retry — see https://instanode.dev/docs.",
	},
	"missing_email": {
		AgentAction: "Tell the user an email address is required. Have them re-submit with a valid email — see https://instanode.dev/docs/auth.",
	},
	"missing_code": {
		AgentAction: "Tell the user the verification code is missing. Have them paste the code from their email and retry at https://instanode.dev/login.",
	},
	// (missing_token already in registry above — auth section)
	"missing_id": {
		AgentAction: "Tell the user the resource id is missing from the path. Re-issue the request with a valid UUID id — see https://instanode.dev/docs.",
	},
	"missing_team_id": {
		AgentAction: "Tell the user no team is associated with this session. Have them log in at https://instanode.dev/login and select a team.",
	},
	"missing_session_id": {
		AgentAction: "Tell the user the session id is missing. Have them re-run the CLI login flow — see https://instanode.dev/docs/cli.",
	},
	"missing_redirect_uri": {
		AgentAction: "Tell the user the redirect_uri is missing. Have them register an OAuth client at https://instanode.dev/app/team and include the URI in the request.",
	},
	"missing_id_token": {
		AgentAction: "Tell the user the OAuth id_token was missing in the callback. Restart the flow at https://instanode.dev/login.",
	},
	"missing_env": {
		AgentAction: "Tell the user this endpoint requires an 'env' field (development | staging | production). Add it and retry — see https://instanode.dev/docs/env.",
	},
	"missing_target_env": {
		AgentAction: "Tell the user the target_env field is required. Specify the destination env (development | staging | production) and retry — see https://instanode.dev/docs/env.",
	},
	"missing_source_env": {
		AgentAction: "Tell the user the source_env field is required. Specify the source env and retry — see https://instanode.dev/docs/env.",
	},
	"missing_target_plan": {
		AgentAction: "Tell the user the target_plan field is required for this billing action. Specify the destination plan (hobby | hobby_plus | pro | growth | team) and retry — see https://instanode.dev/pricing.",
	},
	"missing_reason": {
		AgentAction: "Tell the user a reason is required for this admin action. Add a short reason string and retry — see https://instanode.dev/docs/admin.",
	},
	"missing_tarball": {
		AgentAction: "Tell the user the deployment tarball is missing. POST a multipart form with 'tarball' (.tar.gz, <=50 MiB) — see https://instanode.dev/docs/deploy.",
	},
	"missing_manifest": {
		AgentAction: "Tell the user the stack manifest is missing. POST a multipart form with 'manifest' (YAML) — see https://instanode.dev/docs/stacks.",
	},
	"missing_body": {
		AgentAction: "Tell the user the request body is missing. POST with a JSON body matching the documented schema — see https://instanode.dev/docs.",
	},
	"missing_fields": {
		AgentAction: "Tell the user one or more required fields are missing. Check the response message for the field list and retry — see https://instanode.dev/docs.",
	},
	"missing_backup_id": {
		AgentAction: "Tell the user the backup_id path parameter is missing. Use GET https://instanode.dev/api/v1/backups to find an id and retry.",
	},
	"missing_confirm_slug": {
		AgentAction: "Tell the user the confirm_slug field is required to confirm this destructive action — supply the slug exactly as shown in the prompt and retry — see https://instanode.dev/docs.",
	},
	"name_too_long": {
		// BUG-AUTH-006: do NOT bake a numeric cap into this sentence —
		// the cap varies per endpoint (resource names 1-64; PAT names
		// up to 120; team names up to 200). Each handler's `message`
		// field carries the endpoint-specific limit; agent_action just
		// tells the agent to read that and shorten.
		AgentAction: "Tell the user the 'name' field is too long. Read the exact limit from `message`, shorten the value to fit, and retry — see https://instanode.dev/docs.",
	},
	"body_too_long": {
		AgentAction: "Tell the user the request body exceeded the per-endpoint cap. Shrink the payload — see https://instanode.dev/docs for per-endpoint limits.",
	},
	"env_too_large": {
		AgentAction: "Tell the user the env_vars block is too large. Trim to <=128 keys totalling <=64 KiB and retry — see https://instanode.dev/docs/env.",
	},

	// ── Validation 4xx: invalid format / value ─────────────────────────────
	"invalid_name": {
		AgentAction: "Tell the user the 'name' field is invalid. Use a short human label of 1-64 chars that starts with a letter or digit and contains only letters, numbers, spaces, underscores or dashes — see https://instanode.dev/docs.",
	},
	"invalid_id": {
		AgentAction: "Tell the user the id in the URL path is not a valid UUID. Check the value against the resource list at https://instanode.dev/app and retry.",
	},
	"invalid_payload": {
		AgentAction: "Tell the user the request body could not be parsed. Verify it is valid JSON matching the documented schema — see https://instanode.dev/docs.",
	},
	"invalid_form": {
		AgentAction: "Tell the user the multipart form is malformed. Check the Content-Type boundary and form-field names — see https://instanode.dev/docs.",
	},
	"invalid_env": {
		AgentAction: "Tell the user the env value is invalid. Use lowercase letters, digits, or dashes only (max 32 chars; e.g. development, staging, production) — see https://instanode.dev/docs/env.",
	},
	"invalid_source_env": {
		AgentAction: "Tell the user the source_env value is invalid. Use lowercase letters, digits, or dashes only (max 32 chars) — see https://instanode.dev/docs/env.",
	},
	"invalid_target_env": {
		AgentAction: "Tell the user the target_env value is invalid. Use lowercase letters, digits, or dashes only (max 32 chars) — see https://instanode.dev/docs/env.",
	},
	"invalid_env_key": {
		AgentAction: "Tell the user the env_var key is invalid. Use uppercase letters, digits, and underscores only, starting with a letter — see https://instanode.dev/docs/env.",
	},
	"invalid_env_vars": {
		AgentAction: "Tell the user the env_vars block failed validation. Check key naming + value sizes against the docs at https://instanode.dev/docs/env.",
	},
	"invalid_env_policy": {
		AgentAction: "Tell the user the env_policy JSON is invalid. Confirm the per-env action allowlists at https://instanode.dev/docs/env-policy and retry.",
	},
	"invalid_state": {
		AgentAction: "Tell the user the OAuth state parameter is invalid or expired. Restart the login flow at https://instanode.dev/login.",
	},
	"invalid_signature": {
		AgentAction: "Tell the user the webhook signature did not verify. Confirm the webhook secret in your dashboard and retry — see https://instanode.dev/docs/webhooks.",
	},
	"timestamp_outside_window": {
		AgentAction: "Tell the user the webhook timestamp is outside the accepted ±5-minute window. Stop replaying captured webhook payloads — retry with a fresh delivery. If clock skew is suspected, sync the sender's clock via NTP — see https://instanode.dev/docs/webhooks.",
	},
	"signature_invalid": {
		AgentAction: "Tell the user the request signature failed verification. Confirm the signing key and the canonical request body and retry — see https://instanode.dev/docs.",
	},
	"invalid_tier": {
		AgentAction: "Tell the user the tier value is invalid. Use one of: anonymous, free, hobby, hobby_plus, pro, growth, team — see https://instanode.dev/pricing.",
	},
	"invalid_plan": {
		AgentAction: "Tell the user the plan value is invalid. Use one of the published plans at https://instanode.dev/pricing and retry.",
	},
	"invalid_role": {
		AgentAction: "Tell the user the role value is invalid. Use one of: owner, admin, member, viewer — see https://instanode.dev/docs/team-roles.",
	},
	"invalid_scope": {
		AgentAction: "Tell the user the OAuth scope is invalid. Check the requested scopes against the docs at https://instanode.dev/docs/auth.",
	},
	"invalid_kind": {
		AgentAction: "Tell the user the kind/discriminator value is invalid. Check the docs at https://instanode.dev/docs for the allowed values and retry.",
	},
	"invalid_event_type": {
		AgentAction: "Tell the user the event_type value is unknown. Check the audit-log docs at https://instanode.dev/docs/audit for the allowed kinds.",
	},
	"invalid_window": {
		AgentAction: "Tell the user the time window value is invalid. Use one of the documented windows (1h, 24h, 7d, 30d) — see https://instanode.dev/docs.",
	},
	"invalid_since": {
		AgentAction: "Tell the user the 'since' timestamp is invalid. Use RFC 3339 (e.g. 2026-05-21T00:00:00Z) — see https://instanode.dev/docs.",
	},
	"invalid_limit": {
		AgentAction: "Tell the user the limit value is out of range. Use a positive integer within the documented cap — see https://instanode.dev/docs.",
	},
	"invalid_cursor": {
		AgentAction: "Tell the user the pagination cursor is invalid or expired. Restart the listing without a cursor — see https://instanode.dev/docs.",
	},
	"invalid_sort_by": {
		AgentAction: "Tell the user the sort_by value is invalid. Check the documented sort keys at https://instanode.dev/docs.",
	},
	"invalid_dimensions": {
		AgentAction: "Tell the user the vector dimensions value is invalid. Use a positive integer within the supported range (see https://instanode.dev/docs/vector).",
	},
	"invalid_key": {
		AgentAction: "Tell the user the object key is invalid. Use a non-empty UTF-8 path without traversal (../) — see https://instanode.dev/docs/storage.",
	},
	"invalid_operation": {
		// API-8 (QA 2026-05-29): agent_action enum must match the error message
		// enum exactly. Error message lists GET, PUT, HEAD as accepted — so
		// must this. Drift surfaces as agent advice that contradicts the
		// actual contract.
		AgentAction: "Tell the user the operation value is invalid. Use GET, PUT, or HEAD for /storage/:token/presign — see https://instanode.dev/docs/storage.",
	},
	"path_unsafe": {
		AgentAction: "Tell the user the object path contains unsafe characters. Use a clean UTF-8 path with no '..', leading slash, or empty segments — see https://instanode.dev/docs/storage.",
	},
	"cross_team_session": {
		AgentAction: "Tell the user their session belongs to a different team than the storage token. Re-authenticate as the token's owning team — see https://instanode.dev/docs/auth.",
	},
	"env_load_failed": {
		AgentAction: "Tell the user the persisted environment variables could not be loaded for this stack. Retry the redeploy in 30 seconds — see https://instanode.dev/status. If it keeps failing, email support@instanode.dev with the request_id.",
	},
	"invalid_service": {
		AgentAction: "Tell the user the service value is unknown. Use one of: postgres, redis, mongodb, queue, storage, webhook, vector — see https://instanode.dev/docs.",
	},
	"invalid_port": {
		AgentAction: "Tell the user the port value is out of range. Use an integer between 1 and 65535 — see https://instanode.dev/docs/deploy.",
	},
	"invalid_branch": {
		AgentAction: "Tell the user the branch name is invalid. Use a valid git ref (letters, digits, /._-) — see https://instanode.dev/docs/deploy.",
	},
	"invalid_repo": {
		AgentAction: "Tell the user the GitHub repo identifier is invalid. Use the `owner/name` form — see https://instanode.dev/docs/deploy.",
	},
	"invalid_hostname": {
		AgentAction: "Tell the user the hostname is invalid. Use lowercase letters, digits, and dashes only (RFC 1035) — see https://instanode.dev/docs/custom-domains.",
	},
	"invalid_promo": {
		AgentAction: "Tell the user the promo code is invalid or expired. Check the dashboard at https://instanode.dev/app/billing for active codes.",
	},
	"invalid_team": {
		AgentAction: "Tell the user the team identifier is invalid. Use the team's UUID from https://instanode.dev/app/team and retry.",
	},
	"invalid_team_id": {
		AgentAction: "Tell the user the team_id path/body parameter is not a valid UUID. Check the team list at https://instanode.dev/app/team and retry.",
	},
	"invalid_user_id": {
		AgentAction: "Tell the user the user_id parameter is not a valid UUID. Check the team-member list at https://instanode.dev/app/team and retry.",
	},
	"invalid_note_id": {
		AgentAction: "Tell the user the note_id is not a valid UUID. Check the notes list and retry — see https://instanode.dev/docs/admin.",
	},
	"invalid_link_id": {
		AgentAction: "Tell the user the magic-link id is invalid or expired. Restart the login flow at https://instanode.dev/login.",
	},
	"invalid_approval_id": {
		AgentAction: "Tell the user the approval_id is not a valid UUID. Check the approval link in your email and retry — see https://instanode.dev/docs/promote.",
	},
	"invalid_backup_id": {
		AgentAction: "Tell the user the backup_id is not a valid UUID. List backups at GET https://instanode.dev/api/v1/backups and retry.",
	},
	"invalid_target": {
		AgentAction: "Tell the user the target value is invalid. Check the docs at https://instanode.dev/docs for the allowed targets.",
	},
	"invalid_target_resource_id": {
		AgentAction: "Tell the user the target_resource_id is not a valid UUID. List resources at GET https://instanode.dev/api/v1/resources and retry.",
	},
	"invalid_parent_resource_id": {
		AgentAction: "Tell the user the parent_resource_id is not a valid UUID. Check the resource list at https://instanode.dev/app/resources and retry.",
	},
	"invalid_resource_bindings": {
		AgentAction: "Tell the user the resource_bindings array is malformed. Each binding needs a token + alias — see https://instanode.dev/docs/stacks.",
	},
	"invalid_frequency": {
		AgentAction: "Tell the user the frequency value is invalid. Use one of: hourly, daily, weekly, monthly — see https://instanode.dev/docs.",
	},
	"invalid_variant": {
		AgentAction: "Tell the user the experiment variant value is unknown. Use a variant id from the experiment definition — see https://instanode.dev/docs/experiments.",
	},
	"invalid_ttl_policy": {
		AgentAction: "Tell the user the deploy TTL policy JSON is invalid. Check the docs at https://instanode.dev/docs/deploy-ttl and retry.",
	},
	"invalid_value": {
		AgentAction: "Tell the user the supplied value failed validation. Check the response message for the specific constraint and retry — see https://instanode.dev/docs.",
	},
	"invalid_valid_for_days": {
		AgentAction: "Tell the user the valid_for_days value is out of range. Use a positive integer within the documented cap — see https://instanode.dev/docs.",
	},
	"invalid_manifest": {
		AgentAction: "Tell the user the stack manifest YAML is invalid. Check syntax + required fields — see https://instanode.dev/docs/stacks.",
	},

	// ── Not-found / gone ───────────────────────────────────────────────────
	"webhook_expired": {
		AgentAction: "Tell the user this webhook token has expired. Have them claim their resources at https://instanode.dev/claim before the 24h TTL, or provision a fresh webhook with POST https://instanode.dev/webhook/new.",
	},
	"session_not_found": {
		AgentAction: "Tell the user this CLI login session was not found or has expired. Restart with `instanode auth login` — see https://instanode.dev/docs/cli.",
	},
	"magic_link_not_found": {
		AgentAction: "Tell the user this magic-link is invalid, used, or expired. Request a new one at https://instanode.dev/login.",
	},
	"team_not_found": {
		AgentAction: "Tell the user the team does not exist or they are not a member. Check the team list at https://instanode.dev/app/team.",
	},
	"user_not_found": {
		AgentAction: "Tell the user no account matched. Verify the email at https://instanode.dev/login or sign up there.",
	},
	"note_not_found": {
		AgentAction: "Tell the user this admin note is gone. Refresh the customer view at https://instanode.dev/app/admin and retry.",
	},
	"pod_not_found": {
		AgentAction: "Tell the user the pod is no longer scheduled. Re-deploy from https://instanode.dev/app/deployments or use POST /deploy/:id/redeploy.",
	},
	"target_not_found": {
		AgentAction: "Tell the user the target resource is gone. List resources at https://instanode.dev/app/resources and retry with a valid token.",
	},
	"parent_not_found": {
		AgentAction: "Tell the user the parent resource referenced by this request no longer exists. Re-provision the parent or retarget — see https://instanode.dev/docs.",
	},
	"backup_not_found": {
		AgentAction: "Tell the user the backup id is unknown. List available backups at GET https://instanode.dev/api/v1/backups and retry.",
	},
	"approval_not_found": {
		AgentAction: "Tell the user the approval link is invalid or expired. The team owner can re-issue the approval — see https://instanode.dev/docs/promote.",
	},
	"no_subscription": {
		AgentAction: "Tell the user no active subscription exists for this team. Start one at https://instanode.dev/pricing.",
	},

	// ── Conflict / state errors ────────────────────────────────────────────
	"already_paused": {
		AgentAction: "Tell the user this resource is already paused. No action needed; resume it from https://instanode.dev/app/resources when ready.",
	},
	"already_pending": {
		AgentAction: "Tell the user a matching pending operation is already in flight. Wait for it to settle, or check status at https://instanode.dev/app.",
	},
	"not_active": {
		AgentAction: "Tell the user this resource is not active (paused, suspended, or expired). Resume or re-provision it from https://instanode.dev/app/resources.",
	},
	"not_paused": {
		AgentAction: "Tell the user this resource is not currently paused — the resume action does not apply. Check status at https://instanode.dev/app/resources.",
	},
	"not_pending": {
		AgentAction: "Tell the user this operation is not in the pending state required for this action. Refresh state from https://instanode.dev/app and retry.",
	},
	"not_ready": {
		AgentAction: "Tell the user this resource is not ready yet. Wait for the status to transition to 'active' (poll every 5 s) — see https://instanode.dev/docs.",
	},
	"not_growth": {
		AgentAction: "Tell the user this action requires the Growth plan or higher. Upgrade at https://instanode.dev/pricing.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"tier_unchanged": {
		AgentAction: "Tell the user the team is already on the target tier. No action needed — see https://instanode.dev/app/billing.",
	},
	"same_plan": {
		AgentAction: "Tell the user the requested plan equals the current plan. No action needed — see https://instanode.dev/app/billing.",
	},
	"same_env": {
		AgentAction: "Tell the user the source_env and target_env are identical. Pick different envs and retry — see https://instanode.dev/docs/env.",
	},
	"twin_exists": {
		AgentAction: "Tell the user a twin deployment for this env already exists. Use PATCH or DELETE on it first — see https://instanode.dev/docs/deploy-twins.",
	},
	"duplicate": {
		AgentAction: "Tell the user a duplicate request was detected. Check the existing resource at https://instanode.dev/app and retry only if intentional.",
	},
	"hostname_taken": {
		AgentAction: "Tell the user this hostname is already claimed by another deployment. Pick a different hostname — see https://instanode.dev/docs/custom-domains.",
	},
	"stack_deleting": {
		AgentAction: "Tell the user this stack is currently being deleted and is not available. Wait for the delete to complete — see https://instanode.dev/app/stacks.",
	},
	"approval_already_executed": {
		AgentAction: "Tell the user this promote approval has already been used. No action needed — see https://instanode.dev/docs/promote.",
	},
	"approval_expired": {
		AgentAction: "Tell the user this approval link has expired. Re-request the promote from https://instanode.dev/app and an owner will receive a fresh link.",
	},
	"approval_mismatch": {
		AgentAction: "Tell the user this approval link does not match the in-flight promote. Re-request approval from https://instanode.dev/app.",
	},
	"approval_not_approved": {
		AgentAction: "Tell the user this promote has not been approved yet. Ask the team owner to confirm the email link — see https://instanode.dev/docs/promote.",
	},

	// ── Permission / authn errors ──────────────────────────────────────────
	"email_not_verified": {
		AgentAction: "Tell the user this action requires a verified email. Open the verification link in their inbox or resend it from https://instanode.dev/app/settings.",
	},
	"forbidden_parent_resource": {
		AgentAction: "Tell the user the parent resource belongs to a different team. Have them switch teams at https://instanode.dev/app/team or use a parent they own.",
	},
	"target_cross_team": {
		AgentAction: "Tell the user the target resource belongs to a different team. Have them switch teams at https://instanode.dev/app/team or pick a target they own.",
	},
	"target_type_mismatch": {
		AgentAction: "Tell the user the target resource type does not match the requested operation. Check the resource list at https://instanode.dev/app/resources.",
	},
	"type_mismatch": {
		AgentAction: "Tell the user the resource type does not match the endpoint. Use the correct endpoint for this resource type — see https://instanode.dev/docs.",
	},
	"resource_inactive": {
		AgentAction: "Tell the user this resource is suspended or expired. Resume from https://instanode.dev/app/resources, or provision a fresh one.",
	},
	"not_a_storage_resource": {
		AgentAction: "Tell the user this token is not a /storage/ resource — the presign endpoint only accepts storage tokens. Provision storage at POST https://instanode.dev/storage/new.",
	},
	"unsupported_for_twin": {
		AgentAction: "Tell the user this operation is not supported on twin deployments. Apply it to the parent deployment instead — see https://instanode.dev/docs/deploy-twins.",
	},
	"unsupported_resource_type": {
		AgentAction: "Tell the user this resource type is not supported for this operation. Check the docs at https://instanode.dev/docs for the supported types.",
	},
	"unsupported_type": {
		AgentAction: "Tell the user this type value is not supported for this operation. See https://instanode.dev/docs for the supported types.",
	},
	"service_disabled": {
		AgentAction: "Tell the user this service is disabled on the platform. Check the live status at https://instanode.dev/status; enable it via INSTANT_ENABLED_SERVICES if self-hosting.",
	},
	"variant_mismatch": {
		AgentAction: "Tell the user the experiment variant in the request no longer matches the assigned variant. Refresh the page and retry — see https://instanode.dev/docs/experiments.",
	},
	"unknown_experiment": {
		AgentAction: "Tell the user this experiment id is unknown or has been retired. Check active experiments at https://instanode.dev/app/admin.",
	},

	// ── Billing-specific failures ──────────────────────────────────────────
	"billing_not_configured": {
		AgentAction: "Tell the user billing is not configured on this deployment. Operators must set RAZORPAY_KEY_ID / SECRET — see https://instanode.dev/docs/billing.",
	},
	"downgrade_not_self_serve": {
		AgentAction: "Tell the user downgrades and cancellations are not self-serve. Email support@instanode.dev — see https://instanode.dev/support.",
	},
	"yearly_change_plan_unsupported": {
		AgentAction: "Tell the user yearly subscriptions can't switch plans inline. Cancel the current subscription, then start the new plan at https://instanode.dev/pricing.",
	},
	"grace_expired": {
		AgentAction: "Tell the user the payment grace window has expired and the team has been downgraded. Re-subscribe at https://instanode.dev/pricing to restore access.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},

	// ── Razorpay codes (kept as raw passthrough) ───────────────────────────
	"razorpay_error": {
		AgentAction: "Tell the user Razorpay returned an error completing the payment. Check the error message and retry, or contact support@instanode.dev — see https://instanode.dev/support.",
	},

	// ── Validation 4xx: signature / state ──────────────────────────────────
	"failed_precondition": {
		AgentAction: "Tell the user a precondition for this action failed. Check the response message for the specific state mismatch — see https://instanode.dev/docs.",
	},
	"destructive_ack_required": {
		AgentAction: "Tell the user this destructive action requires an explicit acknowledgement. Re-issue with `ack: true` after confirming — see https://instanode.dev/docs.",
	},
	"slug_mismatch": {
		AgentAction: "Tell the user the slug in the URL does not match the resource. Refresh from https://instanode.dev/app and retry with the correct slug.",
	},
	"env_mismatch": {
		AgentAction: "Tell the user the env in the request does not match the resource's env. Re-issue with the resource's env value — see https://instanode.dev/docs/env.",
	},
	"oauth_failed": {
		AgentAction: "Tell the user the OAuth handshake failed. Restart the login at https://instanode.dev/login and check that the OAuth client is correctly configured.",
	},
	"oauth_not_configured": {
		AgentAction: "Tell the user OAuth is not configured on this deployment. Operators must set GITHUB_CLIENT_ID / GOOGLE_CLIENT_ID — see https://instanode.dev/docs/auth.",
	},
	// (invitation_invalid covered in the auth/token section above)
	"backup_resource_mismatch": {
		AgentAction: "Tell the user this backup belongs to a different resource. List the resource's backups at GET https://instanode.dev/api/v1/resources/<id>/backups and retry.",
	},
	"restore_in_progress": {
		AgentAction: "Tell the user a restore is already in progress on this resource. Wait for it to complete — see https://instanode.dev/app/resources.",
	},
	"backup_not_ready": {
		AgentAction: "Tell the user this backup is still being created. Wait for status='ready' — see https://instanode.dev/app/resources.",
	},
	"family_validate_failed": {
		AgentAction: "Tell the user a tier-family validation failed. Check the docs at https://instanode.dev/pricing for the allowed transitions and retry.",
	},
	"since_too_old": {
		AgentAction: "Tell the user the 'since' value is older than the retention window. Use a more recent timestamp — see https://instanode.dev/docs/audit.",
	},

	// ── 5xx plumbing — domain-specific so the agent doesn't always email support ──
	// Each of these returns 5xx; without an entry here respondError falls
	// back to AgentActionContactSupport ("email support"). For codes whose
	// transient nature suggests "retry with backoff", we surface a sentence
	// that says so explicitly.
	"db_error": {
		AgentAction: "Tell the user the platform database hit a transient error. Retry in 30 seconds with exponential backoff — see https://instanode.dev/status if it persists.",
	},
	"db_failed": {
		AgentAction: "Tell the user the platform database hit a transient error. Retry in 30 seconds with exponential backoff — see https://instanode.dev/status if it persists.",
	},
	"internal_error": {
		AgentAction: "Tell the user something on our side went wrong. Email support@instanode.dev with this request_id, or check https://instanode.dev/status.",
	},
	"lookup_failed": {
		AgentAction: "Tell the user a lookup on the platform backend timed out. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"list_failed": {
		AgentAction: "Tell the user the list operation hit a transient backend error. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"count_failed": {
		AgentAction: "Tell the user the count operation hit a transient backend error. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"fetch_failed": {
		AgentAction: "Tell the user the fetch hit a transient backend error. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"create_failed": {
		AgentAction: "Tell the user the resource could not be created right now. Retry in 30 seconds; if it persists check https://instanode.dev/status.",
	},
	"update_failed": {
		AgentAction: "Tell the user the update could not be persisted right now. Retry in 30 seconds; if it persists check https://instanode.dev/status.",
	},
	"delete_failed": {
		AgentAction: "Tell the user the delete could not be applied right now. Retry in 30 seconds; if it persists check https://instanode.dev/status.",
	},
	"persist_failed": {
		AgentAction: "Tell the user the persistence step failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"compute_update_failed": {
		AgentAction: "Tell the user the deployment update on the compute backend failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"backup_create_failed": {
		AgentAction: "Tell the user creating the backup failed. Retry in 60 seconds — see https://instanode.dev/status.",
	},
	"backup_lookup_failed": {
		AgentAction: "Tell the user looking up the backup failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"restore_create_failed": {
		AgentAction: "Tell the user creating the restore failed. Retry in 60 seconds — see https://instanode.dev/status.",
	},
	"restore_failed": {
		AgentAction: "Tell the user the restore did not complete. Retry in 60 seconds; if it persists email support@instanode.dev — see https://instanode.dev/status.",
	},
	"deletion_request_failed": {
		AgentAction: "Tell the user the team-deletion request failed to persist. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"approval_failed": {
		AgentAction: "Tell the user recording the promote approval failed. Retry the approval link in 30 seconds — see https://instanode.dev/status.",
	},
	"reject_failed": {
		AgentAction: "Tell the user recording the promote rejection failed. Retry the rejection in 30 seconds — see https://instanode.dev/status.",
	},
	"execute_failed": {
		AgentAction: "Tell the user executing the action failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"summary_failed": {
		AgentAction: "Tell the user computing the summary failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"status_failed": {
		AgentAction: "Tell the user reading the status failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"status_lookup_failed": {
		AgentAction: "Tell the user reading the resource status failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"tier_failed": {
		AgentAction: "Tell the user updating the tier failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"upgrade_failed": {
		AgentAction: "Tell the user the tier upgrade could not be applied right now. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"revocation_failed": {
		AgentAction: "Tell the user revoking the session failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"role_lookup_failed": {
		AgentAction: "Tell the user a team-role lookup failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"team_lookup_failed": {
		AgentAction: "Tell the user a team lookup failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"team_creation_failed": {
		AgentAction: "Tell the user creating the team failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"team_has_no_users": {
		AgentAction: "Tell the user this team has no users yet — add an owner before issuing operations against it. See https://instanode.dev/docs/team.",
	},
	"user_creation_failed": {
		AgentAction: "Tell the user creating the user account failed. Retry in 30 seconds; if it persists email support@instanode.dev — see https://instanode.dev/support.",
	},
	"user_upsert_failed": {
		AgentAction: "Tell the user upserting the user record failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"session_failed": {
		AgentAction: "Tell the user the session could not be issued. Retry the login at https://instanode.dev/login.",
	},
	"token_failed": {
		AgentAction: "Tell the user the token could not be minted. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"token_issue_failed": {
		AgentAction: "Tell the user issuing the API token failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"verify_failed": {
		AgentAction: "Tell the user verification failed on the backend. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"sign_failed": {
		AgentAction: "Tell the user signing the response failed on the backend. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"generate_failed": {
		AgentAction: "Tell the user generating the value failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"mark_converted_failed": {
		AgentAction: "Tell the user marking the JWT as converted failed. Retry the claim in 30 seconds — see https://instanode.dev/status.",
	},
	// (deletion_token_invalid covered in the deletion-confirmed section above)
	"encryption_failed": {
		AgentAction: "Tell the user the encryption step failed. Retry in 30 seconds; if it persists email support@instanode.dev with this request_id — see https://instanode.dev/support.",
	},
	"decrypt_failed": {
		AgentAction: "Tell the user decrypting the stored credential failed. Retry in 30 seconds; if it persists email support@instanode.dev with this request_id — see https://instanode.dev/support.",
	},
	"encryption_unavailable": {
		AgentAction: "Tell the user the encryption backend is temporarily unavailable. Retry in 60 seconds — see https://instanode.dev/status.",
	},
	"enqueue_failed": {
		AgentAction: "Tell the user enqueueing the background job failed. Retry the action in 30 seconds — see https://instanode.dev/status.",
	},
	"plans_unavailable": {
		AgentAction: "Tell the user the plans registry is temporarily unavailable. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"pods_unavailable": {
		AgentAction: "Tell the user the deployment pods are unreachable right now. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"provider_failed": {
		AgentAction: "Tell the user the upstream provider hit a transient error. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"vault_ref_failed": {
		AgentAction: "Tell the user resolving the vault reference failed. Confirm the env+key exist at https://instanode.dev/app/vault and retry.",
	},
	"usage_failed": {
		AgentAction: "Tell the user computing usage failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"logs_failed": {
		AgentAction: "Tell the user fetching logs failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"logs_unavailable": {
		AgentAction: "Tell the user logs are temporarily unavailable for this deployment. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"stream_failed": {
		AgentAction: "Tell the user the streaming connection dropped. Re-open the SSE / WebSocket — see https://instanode.dev/docs.",
	},
	"tarball_open_failed": {
		AgentAction: "Tell the user the deployment tarball could not be opened. Verify it is a valid .tar.gz (<=50 MiB) and retry — see https://instanode.dev/docs/deploy.",
	},
	"tarball_read_failed": {
		AgentAction: "Tell the user reading the deployment tarball failed mid-upload. Retry the upload with a clean tarball — see https://instanode.dev/docs/deploy.",
	},
	"tarball_too_large": {
		AgentAction: "Tell the user the deployment tarball exceeded the 50 MiB cap. Trim node_modules / build artefacts and retry — see https://instanode.dev/docs/deploy.",
	},
	"no_services": {
		AgentAction: "Tell the user the stack manifest declared no services. Add at least one service block — see https://instanode.dev/docs/stacks.",
	},
	"no_connection_url": {
		AgentAction: "Tell the user no connection URL is recorded for this resource. Re-provision the resource — see https://instanode.dev/docs.",
	},
	"no_update_url": {
		AgentAction: "Tell the user no update URL is recorded for this checkout. Refresh the billing page at https://instanode.dev/app/billing and restart the upgrade.",
	},
	"pause_failed": {
		AgentAction: "Tell the user the pause action failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"resume_failed": {
		AgentAction: "Tell the user the resume action failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"inflight_check_failed": {
		AgentAction: "Tell the user the in-flight dedup check failed. Retry the action in 30 seconds — see https://instanode.dev/status.",
	},
	"quota_check_failed": {
		AgentAction: "Tell the user the quota check failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"billing_persistence_failed": {
		AgentAction: "Tell the user persisting the billing change failed. Retry the action in 30 seconds; if it persists email support@instanode.dev with this request_id — see https://instanode.dev/support.",
	},

	// ── 429 rate-limited (canonical) ───────────────────────────────────────
	// helpers.go already maps "rate_limit_exceeded"; map "rate_limited"
	// (used by the rate-limit middleware itself).
	"rate_limited": {
		AgentAction: "Tell the user they've been rate-limited. Wait 60 seconds and retry — see https://instanode.dev/docs/rate-limits, or upgrade at https://instanode.dev/pricing for higher limits.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},

	// ── Coverage-test patches (codes discovered by TestErrorCode_HasAgentAction) ──
	"already_connected": {
		AgentAction: "Tell the user a GitHub deployment is already connected to this resource. Disconnect at https://instanode.dev/app/deployments first, then retry.",
	},
	"deployment_limit_reached": {
		AgentAction: "Tell the user they've hit their plan's deployment-app limit. Upgrade at https://instanode.dev/pricing to provision more deploys.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"queue_limit_reached": {
		AgentAction: "Tell the user they've hit their plan's queue-resource limit. Upgrade at https://instanode.dev/pricing to provision more queues.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"github_requires_paid_tier": {
		AgentAction: "Tell the user GitHub auto-deploys require a paid plan (Hobby+). Upgrade at https://instanode.dev/pricing — takes 30 seconds.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"private_deploy_requires_pro": {
		AgentAction: "Tell the user private deployments require the Pro plan or higher. Upgrade at https://instanode.dev/pricing — takes 30 seconds.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"private_deploy_requires_allowed_ips": {
		AgentAction: "Tell the user `private: true` requires an `allowed_ips` array. Add at least one IP/CIDR and retry — see https://instanode.dev/docs/private-deploys.",
	},
	"too_many_allowed_ips": {
		AgentAction: "Tell the user allowed_ips exceeded the documented cap. Trim the list (see the docs at https://instanode.dev/docs/private-deploys for the limit) and retry.",
	},
	"invalid_allowed_ip": {
		AgentAction: "Tell the user an allowed_ips entry is not a valid IP/CIDR. Use IPv4 or IPv6 address-or-CIDR notation — see https://instanode.dev/docs/private-deploys.",
	},
	"invalid_hours": {
		AgentAction: "Tell the user the hours value is invalid. Use a positive integer within the documented cap — see https://instanode.dev/docs/deploy-ttl.",
	},
	"invalid_notify_webhook": {
		AgentAction: "Tell the user the notify_webhook URL is malformed. Use a fully-qualified https URL — see https://instanode.dev/docs/deploy-ttl.",
	},
	"email_send_failed": {
		AgentAction: "Tell the user delivering the email failed. Retry in 60 seconds — see https://instanode.dev/status if it persists.",
	},
	"deletion_create_failed": {
		AgentAction: "Tell the user persisting the deletion request failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"deletion_lookup_failed": {
		AgentAction: "Tell the user looking up the deletion request failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"deletion_mark_failed": {
		AgentAction: "Tell the user marking the deletion as confirmed failed. Retry in 30 seconds — see https://instanode.dev/status.",
	},
	"subscription_cancel_failed": {
		AgentAction: "Tell the user cancelling the Razorpay subscription failed. The team-delete is paused; email support@instanode.dev so an operator can reconcile — see https://instanode.dev/support.",
	},

	// ── Auth content-type gate (AUTH-163, CSRF). Per-IP rate-limit (AUTH-097/107)
	// returns 202 silently per CLAUDE.md "silent absorb" policy — no agent_action needed.
	"invalid_content_type": {
		AgentAction: "Tell the user the magic-link request must use Content-Type: application/json. Form-urlencoded bodies are rejected to prevent CSRF — retry with JSON. See https://instanode.dev/docs/auth.",
	},

	// ── Auth redirect + PAT trust-boundary walls (AUTH-001/002/016/017/090) ──
	"invalid_return_to": {
		AgentAction: "Tell the user the return_to URL is not https:// — javascript: and data: schemes are rejected to prevent open-redirect. Retry with a valid https URL — see https://instanode.dev/docs/auth.",
	},
	"invalid_scopes": {
		AgentAction: "Tell the user the requested PAT scopes are empty or unknown. Pass an explicit non-empty subset of {read,write,admin} — see https://instanode.dev/docs/api-tokens.",
	},
	"pat_cannot_mint_pat": {
		AgentAction: "Tell the user PATs cannot mint child PATs — only session-authenticated requests can create tokens. Sign in at https://instanode.dev/login and re-issue.",
	},
	"reauth_required": {
		AgentAction: "Tell the user this action requires a fresh session (admin-scope PAT mints need re-auth). Sign in again at https://instanode.dev/login — see https://instanode.dev/docs/auth.",
	},
}

// ErrorResponse is the canonical JSON shape for every 4xx/5xx response.
//
// AgentAction and UpgradeURL are omitempty so existing clients (dashboard,
// MCP, CLI) that ignore them see no change.
//
// RequestID is always populated when the request flowed through
// middleware.RequestID() (every production route does) — the field gives
// agents a stable correlator they can echo when emailing support without
// having to read the X-Request-ID header separately.
//
// RetryAfterSeconds is a pointer so we can distinguish "no retry — fix the
// request" (4xx → nil/null in JSON) from "retry in N seconds" (5xx → int).
// Pairs with the Retry-After HTTP header on 429/502/503/504 responses so
// polite HTTP clients honor the same wait without parsing the body.
type ErrorResponse struct {
	OK                bool   `json:"ok"`
	Error             string `json:"error"`
	Message           string `json:"message"`
	RequestID         string `json:"request_id,omitempty"`
	RetryAfterSeconds *int   `json:"retry_after_seconds"`
	AgentAction       string `json:"agent_action,omitempty"`
	UpgradeURL        string `json:"upgrade_url,omitempty"`
	// ClaimURL is populated only on the free-tier recycle gate
	// (error=free_tier_recycle_requires_claim). omitempty keeps the wire
	// shape unchanged for every other error envelope.
	ClaimURL string `json:"claim_url,omitempty"`
}

// defaultRetryAfterSeconds returns the retry-after value that the standard
// envelope writes for a given status code:
//
//   - 503: 30s (provisioning/db transient failures — retry quickly)
//   - 429: 60s (rate-limit window default; per-call override accepted)
//   - 502, 504: 10s (bad gateway / gateway timeout — short retry)
//   - other 5xx: nil (the client cannot know if retry is safe — fix on our side)
//   - 4xx: nil (no retry — fix the request)
//
// A nil result writes `"retry_after_seconds": null` in the JSON body and
// omits the Retry-After header.
func defaultRetryAfterSeconds(status int) *int {
	var v int
	switch status {
	case fiber.StatusServiceUnavailable: // 503
		v = 30
	case fiber.StatusTooManyRequests: // 429
		v = 60
	case fiber.StatusBadGateway, fiber.StatusGatewayTimeout: // 502, 504
		v = 10
	default:
		return nil
	}
	return &v
}

// shouldSetRetryAfterHeader reports whether the HTTP Retry-After header
// should accompany the JSON body for the given status. RFC 7231 §7.1.3
// names 429 + 503 explicitly; 502 + 504 are the other transient-gateway
// codes our infra emits and clients-in-the-wild honor for those too.
func shouldSetRetryAfterHeader(status int) bool {
	switch status {
	case fiber.StatusTooManyRequests,
		fiber.StatusBadGateway,
		fiber.StatusServiceUnavailable,
		fiber.StatusGatewayTimeout:
		return true
	}
	return false
}

// requestIDFromCtx pulls the request_id Fiber local populated by
// middleware.RequestID() in the production chain. Returns "" if the
// middleware didn't run (e.g. a test that didn't register it) — the
// JSON field is omitempty so the wire shape stays clean either way.
//
// Kept here (not imported from middleware) to avoid an import cycle:
// middleware imports handlers/* in several spots already.
func requestIDFromCtx(c *fiber.Ctx) string {
	if v, ok := c.Locals("request_id").(string); ok {
		return v
	}
	return ""
}

// respondError writes a structured JSON error and returns ErrResponseWritten.
//
// The envelope ALWAYS includes:
//   - request_id   (from middleware.RequestID; "" when absent)
//   - retry_after_seconds (status-code-driven default; null on 4xx)
//   - agent_action (from codeToAgentAction; falls back to
//     AgentActionContactSupport for 5xx codes without a registry entry)
//
// For 429/502/503/504, the matching Retry-After HTTP header is also set so
// HTTP clients (most agent frameworks, curl --retry-all-errors, etc.) honor
// the same wait without parsing the body.
//
// Always returns a non-nil error so multi-return helpers compose safely:
//
//	teamID, err := h.requireTeamMatch(c)
//	if err != nil { return err }
//
// The caller's `if err != nil` branch fires correctly even when the
// underlying response-write succeeded. Before the ErrResponseWritten
// sentinel landed, respondError returned c.Status().JSON()'s result (nil
// on success), so the caller's check was false and execution continued
// past the validation gate — producing 500s and silent provisioning of
// invalid input.
func respondError(c *fiber.Ctx, status int, code, message string) error {
	resp := ErrorResponse{
		OK:                false,
		Error:             code,
		Message:           message,
		RequestID:         requestIDFromCtx(c),
		RetryAfterSeconds: defaultRetryAfterSeconds(status),
	}
	if meta, ok := codeToAgentAction[code]; ok {
		resp.AgentAction = meta.AgentAction
		resp.UpgradeURL = meta.UpgradeURL
	} else if status >= 500 {
		// Plumbing 5xx with no registry entry: hand the agent a generic
		// "email support with this request_id" sentence so the user always
		// has SOMETHING actionable, instead of an empty agent_action.
		resp.AgentAction = AgentActionContactSupport
	}
	if resp.RetryAfterSeconds != nil && shouldSetRetryAfterHeader(status) {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(*resp.RetryAfterSeconds))
	}
	setSecurityHeadersFor401(c, status)
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}

// setSecurityHeadersFor401 emits the canonical WWW-Authenticate response
// header on every 401 envelope so HTTP-spec-compliant clients (RFC 7235
// §4.1) know which authentication scheme + realm the API expects. Without
// this header, the JSON envelope said "unauthorized" but the wire-level
// HTTP contract was incomplete — an MCP / SDK / browser fetch checking
// HEAD on a protected route had no machine-readable handshake to follow.
//
// realm="instanode" is the canonical realm; agents that recognise the
// realm can offer to re-authenticate without prompting the user
// repeatedly. The scheme is `Bearer` because every authenticated path
// expects `Authorization: Bearer <jwt|pat>` — DPoP-required routes still
// carry the Bearer challenge here because the DPoP scheme is opaque to
// most HTTP libraries; the DPoP middleware sets its own per-route header
// only when DPoP is the only acceptable proof.
//
// No-op for non-401 statuses. Lives next to respondError* so every 401
// path goes through it without scattering c.Set("WWW-Authenticate", ...)
// calls across 20+ handler files.
func setSecurityHeadersFor401(c *fiber.Ctx, status int) {
	if status != fiber.StatusUnauthorized {
		return
	}
	// Only set if not already set by the DPoP middleware (which uses
	// a richer "DPoP algs=..." challenge on routes that require DPoP).
	if existing := c.Get(fiber.HeaderWWWAuthenticate); existing == "" {
		c.Set(fiber.HeaderWWWAuthenticate, `Bearer realm="instanode"`)
	}
}

// respondErrorWithAgentAction writes a structured JSON error with an
// explicit AgentAction (and optionally UpgradeURL) supplied by the caller,
// overriding any default from codeToAgentAction.
//
// Use this when the agent-facing copy needs context the default sentence
// can't carry — e.g. naming the specific tier ("you've hit the *hobby*
// limit") or the specific resource limit value ("storage limit reached
// (500MB)"). For the common path, prefer plain respondError.
//
// Same auto-populated fields as respondError: request_id, retry_after_seconds,
// and the Retry-After header on 429/502/503/504.
func respondErrorWithAgentAction(c *fiber.Ctx, status int, code, message, agentAction, upgradeURL string) error {
	resp := ErrorResponse{
		OK:                false,
		Error:             code,
		Message:           message,
		RequestID:         requestIDFromCtx(c),
		RetryAfterSeconds: defaultRetryAfterSeconds(status),
		AgentAction:       agentAction,
		UpgradeURL:        upgradeURL,
	}
	if resp.RetryAfterSeconds != nil && shouldSetRetryAfterHeader(status) {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(*resp.RetryAfterSeconds))
	}
	setSecurityHeadersFor401(c, status)
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}

// respondRecycleGate writes the canonical 402 envelope for the free-tier
// recycle gate. It goes through the same ErrorResponse path as every other
// error so the envelope carries request_id + retry_after_seconds (previously
// the gate hand-built a fiber.Map and dropped both — P2 finding 2026-05-17).
// claim_url is the recycle-gate-specific field; upgrade_url points at the
// same claim URL because re-claiming clears the gate.
func respondRecycleGate(c *fiber.Ctx, code, message, agentAction, claimURL string) error {
	status := fiber.StatusPaymentRequired
	resp := ErrorResponse{
		OK:                false,
		Error:             code,
		Message:           message,
		RequestID:         requestIDFromCtx(c),
		RetryAfterSeconds: defaultRetryAfterSeconds(status),
		AgentAction:       agentAction,
		UpgradeURL:        claimURL,
		ClaimURL:          claimURL,
	}
	setSecurityHeadersFor401(c, status)
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}

// WriteFiberError is the exported entry point used by the Fiber-level
// ErrorHandler in router/router.go (and the test ErrorHandler in
// testhelpers/testhelpers.go) to wrap Fiber-default errors (404, 405,
// 413, 415, panics → 500) in the same envelope as handler-emitted
// respondError calls.
//
// The router package cannot call the unexported respondError directly
// (lives in a different package); this wrapper preserves encapsulation
// while ensuring "wrong-method 405" and "respondError 4xx" produce the
// identical JSON shape — important for agents that only learn the
// envelope once per service.
func WriteFiberError(c *fiber.Ctx, status int, code, message string) error {
	return respondError(c, status, code, message)
}

// respondProvisionFailed centralizes the 503 response for any
// provisioning path (POST /db/new, /cache/new, /nosql/new, /queue/new,
// /vector/new, twin redeploys). When the provisioner circuit breaker
// is open it returns the more specific `provisioner_unavailable`
// envelope so agents that branch on `error` see a code that signals
// "the dependency itself is down" rather than "your request was
// malformed but I'm returning 503 anyway".
//
// On any other error it returns the original `provision_failed` envelope
// the call sites used to emit by hand — same wire shape as before so
// nothing downstream (CLI, dashboard, MCP) needs to change.
//
// Lives in helpers.go (not provisioner/) so it can import circuit
// without creating an import cycle.
func respondProvisionFailed(c *fiber.Ctx, err error, fallbackMessage string) error {
	if errors.Is(err, circuit.ErrOpen) {
		return respondError(c, fiber.StatusServiceUnavailable, "provisioner_unavailable",
			"The provisioner is temporarily unavailable. Retry in 30 seconds — see https://instanode.dev/status for live status.")
	}
	return respondError(c, fiber.StatusServiceUnavailable, "provision_failed", fallbackMessage)
}

// respondErrorWithRetry is the same as respondError but lets the caller
// override the auto-computed retry_after_seconds. Pass retryAfter < 0 to
// force the field to null even on a status that would normally carry a
// default (e.g. a 503 where the agent should NOT retry because the
// underlying request is malformed in a way only a human can fix).
//
// Most call sites should use respondError (auto-computed) — this exists
// for the handful of paths that know the right wait better than the
// status code does (rate-limit middleware that knows when the window
// resets; queue-overload responses that read backlog depth).
func respondErrorWithRetry(c *fiber.Ctx, status int, code, message string, retryAfter int) error {
	var ra *int
	if retryAfter >= 0 {
		v := retryAfter
		ra = &v
	}
	resp := ErrorResponse{
		OK:                false,
		Error:             code,
		Message:           message,
		RequestID:         requestIDFromCtx(c),
		RetryAfterSeconds: ra,
	}
	if meta, ok := codeToAgentAction[code]; ok {
		resp.AgentAction = meta.AgentAction
		resp.UpgradeURL = meta.UpgradeURL
	} else if status >= 500 {
		resp.AgentAction = AgentActionContactSupport
	}
	if ra != nil && shouldSetRetryAfterHeader(status) {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(*ra))
	}
	setSecurityHeadersFor401(c, status)
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}
