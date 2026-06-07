package middleware

// admin.go — RequireAdmin gates a route on the caller's JWT email matching
// the ADMIN_EMAILS allowlist. Used to expose founder-only "customer
// management" surfaces under /api/v1/admin/* without standing up a separate
// RBAC role or a parallel auth system.
//
// Why an env-var allowlist (not a DB column):
//   - Zero migrations / zero ops to bootstrap.
//   - The list is small (founder + a handful of teammates), changes rarely,
//     and is canonically configured at the platform layer rather than per
//     tenant. Storing it in env keeps the admin set out of any single
//     team's row — there's no "team owner" semantics here.
//   - Closed by default: if ADMIN_EMAILS is empty/unset the middleware
//     rejects every caller. Forgetting to set the var fails closed, not
//     open.
//
// Wiring contract:
//   - MUST be installed AFTER RequireAuth — reads the auth_email Local that
//     RequireAuth populated from the JWT's `email` claim.
//   - Returns 403 with the canonical agent_action body (see
//     handlers.AgentActionAdminRequired) so an LLM agent invoking the route
//     gets a verbatim sentence to relay to the user.

import (
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// AdminEmailsEnvVar is the env var consulted by RequireAdmin. Comma-separated,
// case-insensitive, surrounding whitespace ignored. Named constant so tests
// and audits can grep for the one source of truth.
const AdminEmailsEnvVar = "ADMIN_EMAILS"

// adminForbiddenAgentAction is the canonical agent_action sentence served on
// every 403 from RequireAdmin. Mirrors handlers.AgentActionAdminRequired so
// agents see the same remediation prose whether the rejection happens in
// middleware (missing/empty allowlist, non-admin caller) or in a handler
// that gates a sub-action behind admin (none today, but the constant is
// shared for future use).
//
// Duplicated here rather than imported because middleware is depended on by
// handlers, not the other way around; a cross-import would introduce a
// cycle. The handlers package re-exports the same string as a constant.
const adminForbiddenAgentAction = "Tell the user this endpoint requires platform-admin access. Ask contact@instanode.dev via https://instanode.dev/support if you think this is wrong."

// AdminEmailAllowlist returns the parsed, lowercased ADMIN_EMAILS set. Empty
// when ADMIN_EMAILS is unset or blank. Exported so tests / observability
// surfaces can verify which addresses are currently admin without
// re-implementing the parse rules.
func AdminEmailAllowlist() map[string]bool {
	raw := strings.TrimSpace(os.Getenv(AdminEmailsEnvVar))
	if raw == "" {
		return nil
	}
	out := make(map[string]bool)
	for _, part := range strings.Split(raw, ",") {
		e := strings.ToLower(strings.TrimSpace(part))
		if e != "" {
			out[e] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IsAdminEmail reports whether email is in the ADMIN_EMAILS allowlist.
// Case-insensitive; empty input is never admin. Exported so handlers can
// branch on "is the current caller an admin?" without re-reading env.
func IsAdminEmail(email string) bool {
	if email == "" {
		return false
	}
	allow := AdminEmailAllowlist()
	if len(allow) == 0 {
		return false
	}
	return allow[strings.ToLower(strings.TrimSpace(email))]
}

// RequireAdmin returns a Fiber middleware that rejects any caller whose JWT
// email is not present in ADMIN_EMAILS. Must be installed AFTER RequireAuth.
//
// Closed by default: an empty / unset ADMIN_EMAILS rejects every caller.
// This is the safe failure mode — forgetting to configure the var must
// never silently expose the admin surface.
//
// Response shape on rejection (403):
//
//	{
//	  "ok": false,
//	  "error": "forbidden",
//	  "message": "platform-admin access required",
//	  "request_id": "<x-request-id>",
//	  "retry_after_seconds": null,
//	  "agent_action": "Tell the user this endpoint requires platform-admin access..."
//	}
//
// W12: request_id + retry_after_seconds match the canonical
// handlers.ErrorResponse envelope so agents that learn the shape once can
// inspect any 4xx from this API without per-layer special cases.
func RequireAdmin() fiber.Handler {
	return func(c *fiber.Ctx) error {
		email := GetEmail(c)
		if !IsAdminEmail(email) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"ok":                  false,
				"error":               "forbidden",
				"message":             "platform-admin access required",
				"request_id":          GetRequestID(c),
				"retry_after_seconds": nil,
				"agent_action":        adminForbiddenAgentAction,
			})
		}
		return c.Next()
	}
}
