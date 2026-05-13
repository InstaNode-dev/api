package middleware

// quota.go — HTTP-layer translation of quota errors into RFC 7231 §6.5.2
// "402 Payment Required" responses.
//
// instanode.dev's per-resource throughput and storage quota checks live in
// internal/quota and return plain (exceeded bool, err error). This file
// gives handlers a single place to convert "quota exceeded" into the
// canonical 402 response shape, including the WWW-Authenticate: Payment
// header that future Stripe MPP integration will turn into a paywall.
//
// Today no payment is actually accepted — the response just signals which
// upgrade URL the agent should follow. The header keyword is reserved by
// the in-progress Machine Payments Protocol
// (https://stripe.com/blog/machine-payments-protocol) so when MPP ships
// this becomes a one-PR upgrade.

import (
	"github.com/gofiber/fiber/v2"
)

// QuotaUpgradeURL is the URL agents should follow to clear a 402.
// Plumbed as a package-level variable so tests and self-hosted operators
// can override it (e.g. point at a custom billing portal).
var QuotaUpgradeURL = "https://instanode.dev/pricing"

// quotaExceededAgentAction builds the canonical agent_action sentence served
// on every 402 from PaymentRequired. Mirrors the "quota_exceeded" entry in
// handlers.codeToAgentAction — the U3 contract shape is identical:
//
//   - opens with "Tell the user"
//   - names the specific reason ("plan's usage limit")
//   - exact next action ("upgrade")
//   - full https://instanode.dev/... URL via QuotaUpgradeURL
//
// Built as a function (not a const) because QuotaUpgradeURL is a `var` so
// tests + self-hosted operators can override it — a const would freeze the
// URL at package-init time and silently ignore the override.
//
// Kept as a package-private builder rather than inlined at the call site so
// the contract review (grep "agent_action" internal/middleware) surfaces
// every middleware-level agent_action string in this file alongside
// unauthorizedAgentAction (auth.go) and adminForbiddenAgentAction (admin.go).
// Duplicated rather than imported because middleware is depended on by
// handlers, not the other way around (cross-import would close a cycle —
// same justification as the other two middleware-level constants).
//
// The contract test (handlers.TestAgentActionContract) can't reach into
// middleware without an import cycle, so this builder is exercised by the
// existing PaymentRequired tests which assert the response-body shape.
func quotaExceededAgentAction() string {
	return "Tell the user they've hit their plan's usage limit. To unlock more, have them upgrade at " + QuotaUpgradeURL + "."
}

// PaymentRequired writes a 402 response with the canonical instanode.dev
// shape used across all quota-exceeded paths:
//
//	HTTP/1.1 402 Payment Required
//	WWW-Authenticate: Payment realm="instanode", upgrade_url="https://instanode.dev/pricing"
//	Content-Type: application/json
//
//	{
//	  "ok":false,
//	  "error":"quota_exceeded",
//	  "upgrade_url":"https://instanode.dev/pricing",
//	  "agent_action":"Tell the user they've hit their plan's usage limit..."
//	}
//
// errKey lets callers customise the JSON `error` field for distinct quota
// classes (e.g. "throughput_exceeded", "storage_exceeded"); it falls back
// to the generic "quota_exceeded" when empty so call sites stay terse.
//
// agent_action is the sentence the calling agent should surface verbatim
// to the human user — added per RETRO-2026-05-12 §10.15 so a Claude /
// Cursor / MCP agent hitting this wall knows exactly what to say.
//
// The handler does not actually accept payment yet — the WWW-Authenticate
// header is the forward-compatibility hook for Stripe's Machine Payments
// Protocol. Agents implementing MPP will treat the header as the trigger
// to retry with payment material attached; everyone else just follows
// upgrade_url.
func PaymentRequired(c *fiber.Ctx, errKey string) error {
	if errKey == "" {
		errKey = "quota_exceeded"
	}
	c.Set("WWW-Authenticate",
		`Payment realm="instanode", upgrade_url="`+QuotaUpgradeURL+`"`)
	return c.Status(fiber.StatusPaymentRequired).JSON(fiber.Map{
		"ok":           false,
		"error":        errKey,
		"upgrade_url":  QuotaUpgradeURL,
		"agent_action": quotaExceededAgentAction(),
	})
}
