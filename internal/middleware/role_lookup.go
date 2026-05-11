package middleware

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

// roleLookupDB is the package-level DB handle used by PopulateTeamRole to
// resolve the authenticated user's team role after RequireAuth has set
// LocalKeyUserID and LocalKeyTeamID. Set via SetRoleLookupDB at startup.
var (
	roleLookupMu sync.RWMutex
	roleLookupDB *sql.DB
)

// SetRoleLookupDB registers the platform DB handle used to resolve team roles.
// Wired in router.go after middleware install. A nil DB disables role lookup
// (RequireRole will then deny access for any authenticated request, since
// auth_team_role stays empty).
func SetRoleLookupDB(db *sql.DB) {
	roleLookupMu.Lock()
	defer roleLookupMu.Unlock()
	roleLookupDB = db
}

func getRoleLookupDB() *sql.DB {
	roleLookupMu.RLock()
	defer roleLookupMu.RUnlock()
	return roleLookupDB
}

// PopulateTeamRole is a Fiber middleware that runs after RequireAuth and
// hydrates LocalKeyTeamRole by SELECTing the role from team_members for
// (auth_team_id, auth_user_id). Failures are logged and ignored; the
// downstream RequireRole guard will reject.
func PopulateTeamRole() fiber.Handler {
	return func(c *fiber.Ctx) error {
		userID := GetUserID(c)
		teamID := GetTeamID(c)
		if userID == "" || teamID == "" {
			return c.Next()
		}
		db := getRoleLookupDB()
		if db == nil {
			return c.Next()
		}
		ctx, cancel := context.WithTimeout(c.UserContext(), 750*time.Millisecond)
		defer cancel()
		var role string
		err := db.QueryRowContext(ctx,
			`SELECT role FROM users WHERE id = $1 AND team_id = $2`,
			userID, teamID,
		).Scan(&role)
		if err != nil {
			if err != sql.ErrNoRows {
				slog.Warn("role_lookup.failed", "error", err, "team_id", teamID, "user_id", userID)
			}
			return c.Next()
		}
		if role != "" {
			c.Locals(LocalKeyTeamRole, role)
		}
		return c.Next()
	}
}
