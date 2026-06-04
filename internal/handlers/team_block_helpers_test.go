package handlers_test

// team_block_helpers_test.go — shared helpers for the W3 team-block
// integration suite (team_block_routes_test.go). These cover the team &
// member-management user-flow block (USER-FLOW-INVENTORY-AND-TEST-MATRIX.md
// §F: F1–F11) that, prior to this suite, lived in the route-iterating
// done-bar guard's routeCoverageExemptions with no mapped test.
//
// Mirrors the established W3 billing-block convention
// (billing_block_helpers_test.go): a thin SetupTestDB wrapper + a loud
// skip-when-no-DB guard + DB-backed seed helpers. Helpers here are prefixed
// teamBlock* so they do NOT collide with — and do NOT redefine — the existing
// seedVerifiedTeamUser / seedTeam / seedMember / miniRedis / doJSON /
// decodeBody helpers, which this suite reuses verbatim.
//
// What this suite adds over the existing per-handler tests
// (team_members_test.go, team_self_test.go, env_policy_test.go, …): a single
// app builder (teamBlockApp) that wires EVERY team/member route through the
// PRODUCTION RBAC middleware chain — middleware.RequireRole + PopulateTeamRole
// + RequireWritable, with middleware.SetRoleLookupDB pointed at the real test
// DB — exactly as internal/router/router.go does. The existing per-handler
// tests deliberately omit RequireRole (they probe the in-handler requireOwner
// check in isolation); this suite is the route-layer authz contract the
// done-bar guard's routeTestMap rows point at.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// teamBlockSkipNoDB skips a W3 team-block test when no test Postgres is
// configured. The team block is a real-backend integration surface — these
// tests assert on actual rows in teams/users/team_invitations/audit_log, so a
// missing DB is a loud skip, never a false green. Mirrors
// billingBlockSkipNoDB.
func teamBlockSkipNoDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("W3 team-block integration: TEST_DATABASE_URL not set")
	}
}

// teamBlockDB opens a fresh migrated test DB and returns it with its cleanup.
// Thin wrapper over testhelpers.SetupTestDB so every W3 team-block test reads
// the same way.
func teamBlockDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	return testhelpers.SetupTestDB(t)
}

// teamBlockApp builds a Fiber app that registers every team & member
// management route through the SAME middleware chain production uses
// (internal/router/router.go): a synthetic auth shim sets LocalKeyUserID +
// LocalKeyTeamID (standing in for RequireAuth's JWT validation),
// PopulateTeamRole resolves the caller's REAL role from the DB, and the
// owner/admin-gated routes carry RequireRole / RequireWritable exactly as
// the live router does.
//
// actorUserID / actorTeamID are the seeded identity the synthetic auth shim
// injects. Pass "" for actorUserID to simulate an unauthenticated caller
// (the shim then sets no locals and the RequireRole / handler 401 paths
// fire).
//
// rdb must be a working client (use the existing miniRedis(t) helper) — the
// invite path reads it for rate-limiting and idempotency.
func teamBlockApp(t *testing.T, db *sql.DB, rdb *redis.Client, actorUserID, actorTeamID string) *fiber.App {
	t.Helper()

	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		DashboardBaseURL: "http://localhost:5173",
	}
	mail := email.NewNoop()

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			code := fiber.StatusInternalServerError
			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
			}
			return c.Status(code).JSON(fiber.Map{"ok": false, "error": "internal_error", "message": err.Error()})
		},
	})

	app.Use(middleware.RequestID())
	// Synthetic auth shim — production's RequireAuth sets these two locals
	// after validating the session JWT. We set them directly from the seeded
	// identity so the suite exercises the role/ownership chain without minting
	// real JWTs (the auth surface itself is covered by auth_flow_e2e_test.go).
	app.Use(func(c *fiber.Ctx) error {
		if actorUserID != "" {
			c.Locals(middleware.LocalKeyUserID, actorUserID)
		}
		if actorTeamID != "" {
			c.Locals(middleware.LocalKeyTeamID, actorTeamID)
		}
		return c.Next()
	})

	// PopulateTeamRole resolves auth_team_role from the real DB so RequireRole
	// gates on the seeded user's actual role — production wiring.
	middleware.SetRoleLookupDB(db)
	planReg := plans.Default()

	teamSelfH := handlers.NewTeamSelfHandler(db, planReg)
	teamSettingsH := handlers.NewTeamSettingsHandler(db)
	teamSummaryH := handlers.NewTeamSummaryHandler(db, rdb, planReg)
	envPolicyH := handlers.NewEnvPolicyHandler(db)
	teamMembersH := handlers.NewTeamMembersHandler(db, cfg, planReg, mail, rdb)
	teamsH := handlers.NewTeamsHandler(db, cfg, mail)
	teamDelH := handlers.NewTeamDeletionHandler(db, cfg)

	api := app.Group("/api/v1", middleware.PopulateTeamRole())

	// Team self — GET open to any member; PATCH owner-only + writable.
	api.Get("/team", teamSelfH.Get)
	api.Patch("/team", middleware.RequireRole(middleware.RoleOwner), middleware.RequireWritable(), teamSelfH.Update)

	// Team deletion / restore — owner-only (RequireRole at the route layer).
	api.Delete("/team", middleware.RequireRole(middleware.RoleOwner), teamDelH.Delete)
	api.Post("/team/restore", middleware.RequireRole(middleware.RoleOwner), teamDelH.Restore)

	// Team summary — any member.
	api.Get("/team/summary", teamSummaryH.GetSummary)

	// Team settings — GET any member; PATCH writable + admin.
	api.Get("/team/settings", teamSettingsH.Get)
	api.Patch("/team/settings",
		middleware.RequireWritable(),
		middleware.RequireRole(middleware.RoleAdmin),
		teamSettingsH.Update,
	)

	// Env-policy — GET any member; PUT owner enforced inside the handler
	// (canonical env_policy 403 shape), so NO RequireRole here. Mirrors
	// router.go exactly.
	api.Get("/team/env-policy", envPolicyH.Get)
	api.Put("/team/env-policy", envPolicyH.Put)

	// Members + invitations. RBAC is enforced INSIDE these handlers
	// (requireOwner / owner-or-admin), matching router.go which installs no
	// RequireRole on the members subtree.
	api.Get("/team/members", teamMembersH.ListMembers)
	api.Post("/team/members/invite", teamMembersH.InviteMember)
	api.Post("/team/members/leave", teamMembersH.LeaveTeam)
	api.Delete("/team/members/:user_id", teamMembersH.RemoveMember)
	api.Patch("/team/members/:user_id", teamMembersH.UpdateRole)
	api.Post("/team/members/:user_id/promote-to-primary", teamMembersH.PromoteToPrimary)
	api.Get("/team/invitations", teamMembersH.ListInvitations)
	api.Delete("/team/invitations/:id", teamMembersH.RevokeInvitation)
	api.Post("/team/invitations/:id/accept", teamMembersH.AcceptInvitation)

	// Plural-teams invitation alias — admin-only (RequireRole), team-match
	// enforced inside the handler.
	api.Delete("/teams/:team_id/invitations/:id", middleware.RequireRole(middleware.RoleAdmin), teamsH.RevokeInvitation)

	return app
}

// teamBlockSeedTeamOwner inserts a team at the given tier plus its primary
// owner, returning (teamID, ownerID). Registers cleanup. Built on the package
// testhelpers seeders — does NOT redefine seedVerifiedTeamUser/seedMember.
func teamBlockSeedTeamOwner(t *testing.T, db *sql.DB, tier string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, tier))
	owner, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM users WHERE team_id = $1`, teamID)
		db.Exec(`DELETE FROM teams WHERE id = $1`, teamID)
	})
	return teamID, owner.ID
}

// teamBlockAddMember adds a non-owner user with the given role to teamID and
// returns its id.
func teamBlockAddMember(t *testing.T, db *sql.DB, teamID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	u, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", role)
	require.NoError(t, err)
	return u.ID
}

// teamBlockReq issues a request to the test app and returns (status, decoded
// JSON body). Body may be nil. Thin wrapper so every team-block test reads the
// same; built on net/http + app.Test, not redefining doJSON (which takes a
// headers map — this variant needs none).
func teamBlockReq(t *testing.T, app *fiber.App, method, path string, body any) (int, map[string]any) {
	t.Helper()
	resp := doJSON(t, app, method, path, body, nil)
	return resp.StatusCode, decodeBody(t, resp)
}

// teamBlockTeamName reads back a team's name column so a test can assert a
// PATCH persisted.
func teamBlockTeamName(t *testing.T, db *sql.DB, teamID uuid.UUID) string {
	t.Helper()
	var name sql.NullString
	require.NoError(t,
		db.QueryRow(`SELECT name FROM teams WHERE id = $1`, teamID).Scan(&name),
		"read team name")
	return name.String
}

// teamBlockUserRole reads back a user's role column.
func teamBlockUserRole(t *testing.T, db *sql.DB, teamID, userID uuid.UUID) string {
	t.Helper()
	role, err := models.GetUserRole(context.Background(), db, teamID, userID)
	require.NoError(t, err, "read user role")
	return role
}

// teamBlockNotFoundOK is satisfied for the cross-team-isolation assertions:
// acting on another team's resource must NEVER succeed. We accept the
// documented refusal codes (403 forbidden / 404 not_found) and reject any 2xx.
func teamBlockNotFoundOK(status int) bool {
	return status == http.StatusForbidden || status == http.StatusNotFound
}
