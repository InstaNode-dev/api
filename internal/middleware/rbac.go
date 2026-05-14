package middleware

import (
	"github.com/gofiber/fiber/v2"
)

// forbiddenAgentAction is the canonical agent_action sentence served on
// every 403 from RequireRole (insufficient team role). Mirrors the
// "forbidden" entry in handlers.codeToAgentAction so an agent inspecting
// a middleware-emitted 403 (e.g. a viewer trying to call
// /team/invitations) sees the same remediation prose as a
// handler-emitted 403 (e.g. a non-owner trying to delete the team).
const forbiddenAgentAction = "Tell the user they don't have permission for this action. Have them confirm they're logged in to the right team at https://instanode.dev/app/team."

// LocalKeyTeamRole is the fiber.Locals key for the authenticated user's role
// on their team (one of: owner, admin, developer, viewer, member).
//
// Populated by RequireAuth after a successful JWT validation, via a SELECT
// against team_members / users.role for (auth_team_id, auth_user_id).
const LocalKeyTeamRole = "auth_team_role"

// RBAC role constants. Mirrors models.Role* — duplicated here to avoid a
// middleware->models import cycle (middleware is depended on by handlers,
// and models is depended on by handlers).
const (
	RoleOwner     = "owner"
	RoleAdmin     = "admin"
	RoleDeveloper = "developer"
	RoleViewer    = "viewer"

	// roleLegacyMember is treated as developer-equivalent for RBAC purposes:
	// "member" was the only non-owner role before the RBAC split landed.
	roleLegacyMember = "member"
)

// roleRank assigns each role an integer rank for hierarchy comparisons.
// Higher rank = more privileges. Unknown roles rank as -1 (deny).
//
//   owner     = 4
//   admin     = 3
//   developer = 2 (also "member" for legacy compat)
//   viewer    = 1
func roleRank(role string) int {
	switch role {
	case RoleOwner:
		return 4
	case RoleAdmin:
		return 3
	case RoleDeveloper, roleLegacyMember:
		return 2
	case RoleViewer:
		return 1
	default:
		return -1
	}
}

// GetTeamRole retrieves the authenticated user's role from Fiber locals,
// or "" if not set. Returns "owner", "admin", "developer", or "viewer".
func GetTeamRole(c *fiber.Ctx) string {
	if v, ok := c.Locals(LocalKeyTeamRole).(string); ok {
		return v
	}
	return ""
}

// RequireRole returns a Fiber middleware that gates the request on the
// authenticated user having at least the minimum role. Hierarchy is:
//
//	owner > admin > developer > viewer
//
// Examples:
//
//	RequireRole("developer") -> owner, admin, developer pass; viewer is rejected
//	RequireRole("admin")     -> owner, admin pass; developer, viewer rejected
//	RequireRole("viewer")    -> all four roles pass
//
// Must be installed AFTER RequireAuth so that auth_team_role is populated.
// Returns 403 forbidden / 401 unauthorized on failure.
func RequireRole(min string) fiber.Handler {
	required := roleRank(min)
	return func(c *fiber.Ctx) error {
		// auth_user_id must already be set (RequireAuth must run first).
		// Route through respondUnauthorized so the envelope (message,
		// request_id, retry_after_seconds, agent_action, upgrade_url) is
		// identical to every other middleware-emitted 401 (W12).
		if GetUserID(c) == "" {
			return respondUnauthorized(c)
		}
		actor := GetTeamRole(c)
		if roleRank(actor) < required {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"ok":                  false,
				"error":               "forbidden",
				"message":             "Insufficient role: requires at least " + min,
				"request_id":          GetRequestID(c),
				"retry_after_seconds": nil,
				"agent_action":        forbiddenAgentAction,
			})
		}
		return c.Next()
	}
}
