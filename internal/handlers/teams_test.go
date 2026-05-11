package handlers_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

// teamsApp builds a Fiber app wired to the real handler set used in production
// for the RBAC invite endpoints, plus a fake-auth middleware that injects
// (user_id, team_id, team_role) directly so the test can drive RBAC without
// minting JWTs.
//
// Routes registered (mirror what router.go will add):
//
//	POST   /api/v1/teams/:team_id/invitations          (admin gate)
//	GET    /api/v1/teams/:team_id/invitations          (admin gate)
//	DELETE /api/v1/teams/:team_id/invitations/:id      (admin gate)
//	POST   /api/v1/invitations/:token/accept           (no auth)
func teamsApp(t *testing.T, db *sql.DB, actorUserID, actorTeamID, actorRole string) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		DashboardBaseURL: "http://localhost:5173",
	}
	mail := email.New("") // noop client — never actually sends

	app := fiber.New(fiber.Config{
		// respondError already wrote the body — short-circuit so the
		// generic ErrorHandler does not overwrite 4xx with 500.
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

	// Fake auth: inject user/team/role into Locals so RequireRole can decide.
	fakeAuth := func(c *fiber.Ctx) error {
		if actorUserID != "" {
			c.Locals(middleware.LocalKeyUserID, actorUserID)
		}
		if actorTeamID != "" {
			c.Locals(middleware.LocalKeyTeamID, actorTeamID)
		}
		if actorRole != "" {
			c.Locals(middleware.LocalKeyTeamRole, actorRole)
		}
		return c.Next()
	}

	teamsH := handlers.NewTeamsHandler(db, cfg, mail)

	authedAdmin := app.Group("/api/v1/teams/:team_id/invitations", fakeAuth, middleware.RequireRole("admin"))
	authedAdmin.Post("", teamsH.CreateInvitation)
	authedAdmin.Get("", teamsH.ListInvitations)
	authedAdmin.Delete("/:id", teamsH.RevokeInvitation)

	app.Post("/api/v1/invitations/:token/accept", teamsH.AcceptInvitation)
	return app
}

// teamsAppNeedsDB skips the test when no TEST_DATABASE_URL is set.
// Returns the DB and a cleanup.
func teamsAppNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("teams_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// seedTeam inserts a team and a single owner user. Returns (teamID, ownerID).
func seedTeam(t *testing.T, db *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	ownerEmail := testhelpers.UniqueEmail(t)
	user, err := models.CreateUser(ctx, db, teamID, ownerEmail, "", "", "owner")
	require.NoError(t, err)
	return teamID, user.ID
}

// seedExtraUser creates a user on the same team with a given role.
func seedExtraUser(t *testing.T, db *sql.DB, teamID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	user, err := models.CreateUser(context.Background(), db,
		teamID, testhelpers.UniqueEmail(t), "", "", role)
	require.NoError(t, err)
	return user.ID
}

func postJSON(t *testing.T, app *fiber.App, path string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func decode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// TestInvite_OwnerCanInvite — happy path: owner POST returns 201 and a token.
func TestInvite_OwnerCanInvite(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)

	app := teamsApp(t, db, ownerID.String(), teamID.String(), "owner")
	resp := postJSON(t, app, "/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"})

	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decode(t, resp)
	assert.Equal(t, true, body["ok"])
	inv, _ := body["invitation"].(map[string]any)
	require.NotNil(t, inv)
	assert.NotEmpty(t, inv["token"])
	assert.Equal(t, "developer", inv["role"])
}

// TestInvite_AdminCanInvite — admin role passes RequireRole("admin").
func TestInvite_AdminCanInvite(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeam(t, db)
	adminID := seedExtraUser(t, db, teamID, "admin")

	app := teamsApp(t, db, adminID.String(), teamID.String(), "admin")
	resp := postJSON(t, app, "/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "viewer"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestInvite_DeveloperCannotInvite — developer is below the admin gate.
func TestInvite_DeveloperCannotInvite(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeam(t, db)
	devID := seedExtraUser(t, db, teamID, "developer")

	app := teamsApp(t, db, devID.String(), teamID.String(), "developer")
	resp := postJSON(t, app, "/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "viewer"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestInvite_ViewerCannotInvite — viewer is the lowest tier; clearly blocked.
func TestInvite_ViewerCannotInvite(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeam(t, db)
	viewerID := seedExtraUser(t, db, teamID, "viewer")

	app := teamsApp(t, db, viewerID.String(), teamID.String(), "viewer")
	resp := postJSON(t, app, "/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "viewer"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestInvite_TokenSingleUse — accepting twice returns 410 Gone.
func TestInvite_TokenSingleUse(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)

	inviteEmail := testhelpers.UniqueEmail(t)
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID, inviteEmail, "developer", ownerID)
	require.NoError(t, err)

	// Need an app — actor identity doesn't matter for AcceptInvitation (no auth).
	app := teamsApp(t, db, "", "", "")

	r1 := postJSON(t, app, "/api/v1/invitations/"+inv.Token+"/accept", nil)
	require.Equal(t, http.StatusOK, r1.StatusCode, "first accept must succeed")
	body := decode(t, r1)
	assert.NotEmpty(t, body["session_token"], "first accept must mint a session JWT")

	r2 := postJSON(t, app, "/api/v1/invitations/"+inv.Token+"/accept", nil)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusGone, r2.StatusCode, "second accept must return 410")
}

// TestInvite_TokenExpiry — > 7 days old returns 410 Gone.
func TestInvite_TokenExpiry(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)

	// Create the row, then backdate expires_at to simulate a stale invite.
	inviteEmail := testhelpers.UniqueEmail(t)
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID, inviteEmail, "developer", ownerID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE team_invitations SET expires_at = $1 WHERE id = $2`,
		time.Now().Add(-1*time.Hour), inv.ID)
	require.NoError(t, err)

	app := teamsApp(t, db, "", "", "")
	resp := postJSON(t, app, "/api/v1/invitations/"+inv.Token+"/accept", nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestInvite_LastOwnerProtected — last remaining owner cannot leave or be downgraded.
//
// EnsureNotLastOwner guards CreatePersonalTeamAndReassignUser-style flows. Direct
// model assertion (no HTTP) since the dashboard "leave team" surface lives in
// team_members.go (legacy handler) and the corresponding RBAC-aware UX is not
// part of this PR — the helper is in place for Phase 4 to wire.
func TestInvite_LastOwnerProtected(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)
	ctx := context.Background()

	// Sole owner: must be blocked.
	err := models.EnsureNotLastOwner(ctx, db, teamID, ownerID)
	require.ErrorIs(t, err, models.ErrLastOwner)

	// Add a second owner: now the original owner is no longer "last" — allowed.
	_ = seedExtraUser(t, db, teamID, "owner")
	err = models.EnsureNotLastOwner(ctx, db, teamID, ownerID)
	assert.NoError(t, err)
}

// TestInvite_TeamIDMismatch — actor's JWT team must match :team_id path param.
func TestInvite_TeamIDMismatch(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamA, ownerA := seedTeam(t, db)
	teamB, _ := seedTeam(t, db)

	// Actor is owner of team A; tries to act on team B.
	app := teamsApp(t, db, ownerA.String(), teamA.String(), "owner")
	resp := postJSON(t, app, "/api/v1/teams/"+teamB.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "viewer"})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestInvite_RoleValidation — only admin/developer/viewer are valid invite roles.
func TestInvite_RoleValidation(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)

	app := teamsApp(t, db, ownerID.String(), teamID.String(), "owner")

	for _, badRole := range []string{"owner", "root", "", "admin\""} {
		t.Run(fmt.Sprintf("role=%q", badRole), func(t *testing.T) {
			resp := postJSON(t, app, "/api/v1/teams/"+teamID.String()+"/invitations",
				map[string]string{"email": testhelpers.UniqueEmail(t), "role": badRole})
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

// TestInvite_RevokeFlow — owner can revoke a pending invite.
func TestInvite_RevokeFlow(t *testing.T) {
	db, cleanup := teamsAppNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeam(t, db)

	inv, err := models.CreateRBACInvitation(context.Background(), db,
		teamID, testhelpers.UniqueEmail(t), "developer", ownerID)
	require.NoError(t, err)

	app := teamsApp(t, db, ownerID.String(), teamID.String(), "owner")
	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/teams/"+teamID.String()+"/invitations/"+inv.ID.String(), nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Token should now refuse to accept.
	r2 := postJSON(t, app, "/api/v1/invitations/"+inv.Token+"/accept", nil)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusGone, r2.StatusCode)
}
