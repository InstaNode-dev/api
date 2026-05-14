package middleware

// require_writable.go — gates mutating routes against the read_only JWT
// flag set by the platform-admin impersonation flow.
//
// What it does:
//
//   - Reads LocalKeyReadOnly (populated by RequireAuth / OptionalAuth from
//     the JWT's `read_only` claim).
//   - If the flag is true, returns 403 with the canonical agent_action
//     handlers.AgentActionReadOnlySession so an LLM agent steering a
//     mutating call from inside an admin's view-as-customer impersonation
//     session gets verbatim copy to relay ("this is a read-only
//     impersonated session, switch back at https://instanode.dev/app").
//   - Otherwise hands off to the next handler, untouched.
//
// Where it lives in the chain:
//
//   The router installs it on the /api/v1 group (after RequireAuth +
//   PopulateTeamRole) and on the /deploy group, and inline on every
//   top-level POST/PATCH/PUT/DELETE that an impersonated bearer could
//   conceivably hit (POST /db/new, /cache/new, /nosql/new, /queue/new,
//   /storage/new, /webhook/new, /stacks/*, etc.). The impersonation-mint
//   endpoint itself is the only deliberate exception — the admin minting
//   the read-only token holds a normal (writable) session, so the gate
//   would never fire there, but the spec calls out the exemption
//   explicitly so the audit comment in router.go reads cleanly.
//
// Why a middleware (not a per-handler check):
//
//   The read_only flag is irrevocable for the session's lifetime — there
//   is no "downgrade to writable" path within a single token's validity.
//   Centralising the check on the route boundary keeps the policy at the
//   one place an auditor needs to grep: the router. Handlers stay free of
//   "if read_only return 403" boilerplate, and the U3 contract test
//   exercises the one agent_action string the middleware emits.

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// readOnlyForbiddenAgentAction mirrors handlers.AgentActionReadOnlySession.
// Duplicated here rather than imported because middleware is depended on by
// handlers (not the other way around); a cross-import would introduce a
// cycle. The handlers package keeps its own copy, and the U3 contract test
// exercises that constant — touching either string without the other is the
// regression we want CI to catch.
const readOnlyForbiddenAgentAction = "Tell the user this is a read-only impersonated session. Mutations are disabled. Switch back to your real account at https://instanode.dev/app to make changes."

// mutatingMethods is the closed set of HTTP verbs RequireWritable gates.
// GET / HEAD / OPTIONS fall through unconditionally — an impersonated
// session's whole purpose is to *read* the customer's data. Set-membership
// is one switch on the request method; cheaper than a map lookup on the
// hot path.
//
// Listed as constants (not a slice) so reviewers can grep for the exact
// set this gate enforces. A new method (PATCH was already standard,
// CONNECT etc. would be the future) would need a deliberate addition.
const (
	methodPOST   = "POST"
	methodPUT    = "PUT"
	methodPATCH  = "PATCH"
	methodDELETE = "DELETE"
)

// isMutatingMethod reports whether method is one of the four verbs
// RequireWritable gates. Exposed so future audit/log emitters can ask the
// same question without re-encoding the set.
func isMutatingMethod(method string) bool {
	switch method {
	case methodPOST, methodPUT, methodPATCH, methodDELETE:
		return true
	}
	return false
}

// RequireWritable returns a Fiber middleware that rejects mutating
// requests (POST/PUT/PATCH/DELETE) from a read-only (impersonation)
// session with 403 + the canonical agent_action. MUST be installed AFTER
// RequireAuth / OptionalAuth — both of those populate LocalKeyReadOnly
// from the JWT.
//
// GET / HEAD / OPTIONS fall through unconditionally so the impersonated
// admin can still browse the customer's dashboard — view-as-customer is
// exactly what this middleware enables. Non-impersonated sessions also
// fall through with a single bool-check (the hot path).
//
// Response shape on rejection (403):
//
//	{
//	  "ok": false,
//	  "error": "read_only_session",
//	  "message": "this session is read-only (admin impersonation) — mutations are disabled",
//	  "request_id": "<x-request-id>",
//	  "retry_after_seconds": null,
//	  "agent_action": "Tell the user this is a read-only impersonated session..."
//	}
//
// `read_only_session` is distinct from the generic "forbidden" code so an
// agent inspecting the response can branch on "I need to ask the user to
// switch back" without a substring match on the agent_action prose.
//
// W12: request_id + retry_after_seconds match the canonical
// handlers.ErrorResponse envelope so the impersonation gate's body has the
// same field set as any other 4xx from this API.
func RequireWritable() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Fast path: non-impersonated sessions are the vast majority of
		// traffic. One bool-check, then c.Next().
		if !IsReadOnly(c) {
			return c.Next()
		}
		// Impersonated session — let reads through, gate the writes.
		if !isMutatingMethod(c.Method()) {
			return c.Next()
		}
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"ok":                  false,
			"error":               "read_only_session",
			"message":             "this session is read-only (admin impersonation) — mutations are disabled",
			"request_id":          GetRequestID(c),
			"retry_after_seconds": nil,
			"agent_action":        readOnlyForbiddenAgentAction,
		})
	}
}
