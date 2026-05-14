package handlers

import (
	"errors"
	"strconv"

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
	"tier_unavailable": {
		AgentAction: "Tell the user this resource type isn't available on their plan. Upgrade to Pro at https://instanode.dev/pricing to unlock it.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},
	"rate_limit_exceeded": {
		AgentAction: "Tell the user they've sent too many requests in a short window. Wait 60 seconds and retry — or upgrade to Pro at https://instanode.dev/pricing for higher limits.",
		UpgradeURL:  "https://instanode.dev/pricing",
	},

	// ── Auth / token errors ────────────────────────────────────────────────
	"unauthorized": {
		AgentAction: "Tell the user their INSTANODE_TOKEN is missing or invalid. Have them log in at https://instanode.dev/login to mint a new one — takes 30 seconds.",
	},
	"auth_required": {
		AgentAction: "Tell the user this action requires an authenticated session. Have them log in or sign up at https://instanode.dev/login — both flows mint a token.",
	},
	"invalid_token": {
		AgentAction: "Tell the user their INSTANODE_TOKEN is invalid or expired. Have them log in at https://instanode.dev/login to mint a new one.",
	},
	"missing_token": {
		AgentAction: "Tell the user no INSTANODE_TOKEN was provided. Have them log in at https://instanode.dev/login and pass it via Authorization: Bearer <token>.",
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
	_ = c.Status(status).JSON(resp)
	return ErrResponseWritten
}
