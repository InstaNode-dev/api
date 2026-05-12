package handlers

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

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
//     provision_failed) are deliberately omitted — they're transient and
//     the agent should retry, not show prose to the user.
var codeToAgentAction = map[string]errorCodeMeta{
	// ── Quota walls ────────────────────────────────────────────────────────
	"quota_exceeded": {
		AgentAction: "Tell the user they've hit their plan's usage limit. To unlock more, have them upgrade at https://instanode.dev/pricing.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"storage_limit_reached": {
		AgentAction: "Tell the user they've hit their storage limit for this plan. Have them upgrade at https://instanode.dev/pricing to provision larger or additional resources.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_quota_exceeded": {
		AgentAction: "Tell the user they've hit their vault entry quota. Have them upgrade at https://instanode.dev/pricing to add more secrets.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_not_available": {
		AgentAction: "Tell the user the vault feature isn't available on their current plan. Have them upgrade at https://instanode.dev/pricing to use it.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"vault_env_not_allowed": {
		AgentAction: "Tell the user their plan only allows the default vault environment; multi-env vault requires Pro or higher. Upgrade at https://instanode.dev/pricing.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"member_limit": {
		AgentAction: "Tell the user they've hit the team member limit for their plan. Have them upgrade at https://instanode.dev/pricing to add more teammates.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"upgrade_required": {
		AgentAction: "Tell the user this feature requires a higher plan. Have them upgrade at https://instanode.dev/pricing.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"tier_unavailable": {
		AgentAction: "Tell the user this resource type is not available on their current plan. Have them upgrade at https://instanode.dev/pricing.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"rate_limit_exceeded": {
		AgentAction: "Tell the user they've sent too many requests in a short window. Have them wait a minute and retry, or upgrade at https://instanode.dev/pricing for higher limits.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},

	// ── Auth / token errors ────────────────────────────────────────────────
	"unauthorized": {
		AgentAction: "The user's INSTANODE_TOKEN is missing or invalid. Have them log in at https://instanode.dev/login to mint a new one.",
	},
	"auth_required": {
		AgentAction: "This action requires an authenticated user. Have them log in at https://instanode.dev/login (or sign up — both flows mint a token).",
	},
	"invalid_token": {
		AgentAction: "The user's INSTANODE_TOKEN is invalid or expired. Have them log in at https://instanode.dev/login to mint a new one.",
	},
	"missing_token": {
		AgentAction: "No INSTANODE_TOKEN was provided. Have the user log in at https://instanode.dev/login and pass the token in Authorization: Bearer <token>.",
	},
	"vault_requires_auth": {
		AgentAction: "Vault access requires an authenticated session. Have the user log in at https://instanode.dev/login.",
	},
	"invitation_invalid": {
		AgentAction: "This invitation link is invalid or has already been used. Ask the team owner to send a fresh invitation.",
	},
	"already_accepted": {
		AgentAction: "This invitation has already been accepted. The user is already on the team — no action needed.",
	},
	"already_claimed": {
		AgentAction: "These resources have already been claimed by another account. If the user believes this is wrong, have them contact support@instanode.dev.",
	},

	// ── Expired / gone ─────────────────────────────────────────────────────
	"webhook_inactive": {
		AgentAction: "This webhook token has expired or been deactivated. Have the user provision a fresh one with POST /webhook/new.",
	},
	"resource_not_found": {
		AgentAction: "This resource no longer exists. It may have expired (anonymous resources auto-expire after 24h). Have the user provision a fresh one with POST /{type}/new.",
	},

	// ── Permission denied ──────────────────────────────────────────────────
	"forbidden": {
		AgentAction: "The user does not have permission for this action. If they expected access, double-check they're logged in to the right team.",
	},
	"last_owner": {
		AgentAction: "The team needs at least one owner. Have the user promote another member to owner before changing or removing this one.",
	},
}

// ErrorResponse is the canonical JSON shape for every 4xx/5xx response.
// AgentAction and UpgradeURL are omitempty so existing clients (dashboard,
// MCP, CLI) that ignore them see no change.
type ErrorResponse struct {
	OK          bool   `json:"ok"`
	Error       string `json:"error"`
	Message     string `json:"message"`
	AgentAction string `json:"agent_action,omitempty"`
	UpgradeURL  string `json:"upgrade_url,omitempty"`
}

// respondError writes a structured JSON error and returns ErrResponseWritten.
//
// If `code` is in codeToAgentAction, the response also carries an
// `agent_action` field (and, where relevant, `upgrade_url`) — copy the
// agent can surface to the human user.
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
		OK:      false,
		Error:   code,
		Message: message,
	}
	if meta, ok := codeToAgentAction[code]; ok {
		resp.AgentAction = meta.AgentAction
		resp.UpgradeURL = meta.UpgradeURL
	}
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}

// respondErrorWithAgentAction writes a structured JSON error with an
// explicit AgentAction (and optionally UpgradeURL) supplied by the caller,
// overriding any default from codeToAgentAction.
//
// Use this when the agent-facing copy needs context the default sentence
// can't carry — e.g. naming the specific tier ("you've hit the *hobby*
// limit") or the specific resource limit value ("storage limit reached
// (500MB)"). For the common path, prefer plain respondError.
func respondErrorWithAgentAction(c *fiber.Ctx, status int, code, message, agentAction, upgradeURL string) error {
	resp := ErrorResponse{
		OK:          false,
		Error:       code,
		Message:     message,
		AgentAction: agentAction,
		UpgradeURL:  upgradeURL,
	}
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}
