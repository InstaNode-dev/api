package handlers_test

// team_members_test.go — FIX-F coverage for the team admin endpoints:
//
//   PATCH /api/v1/team/members/:user_id                       (UpdateRole)
//   POST  /api/v1/team/members/:user_id/promote-to-primary    (PromoteToPrimary)
//   DELETE /api/v1/team/members/:user_id                      (RemoveMember)
//   POST  /api/v1/team/members/invite                         (InviteMember)
//
// Covers BugBash 47, 48, 49, 50, 52, 53, 54, 55, A5, Q60, Q61.
//
// Skips when TEST_DATABASE_URL is unset (matches the convention in
// teams_test.go and users_is_primary_test.go).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// teamMembersApp wires the FIX-F endpoints onto a Fiber app with fake auth.
//
// We deliberately don't install RequireRole here — every owner-only handler
// (UpdateRole, PromoteToPrimary, RemoveMember) checks ownership *inside*
// the handler via requireOwner(), which is the surface we want under test.
func teamMembersApp(t *testing.T, db *sql.DB, rdb *redis.Client, actorUserID, actorTeamID string) *fiber.App {
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

	app.Use(func(c *fiber.Ctx) error {
		if actorUserID != "" {
			c.Locals(middleware.LocalKeyUserID, actorUserID)
		}
		if actorTeamID != "" {
			c.Locals(middleware.LocalKeyTeamID, actorTeamID)
		}
		return c.Next()
	})

	h := handlers.NewTeamMembersHandler(db, cfg, plans.Default(), mail, rdb)
	app.Get("/api/v1/team/members", h.ListMembers)
	app.Post("/api/v1/team/members/invite", h.InviteMember)
	app.Delete("/api/v1/team/members/:user_id", h.RemoveMember)
	app.Patch("/api/v1/team/members/:user_id", h.UpdateRole)
	app.Post("/api/v1/team/members/:user_id/promote-to-primary", h.PromoteToPrimary)
	app.Post("/api/v1/team/invitations/:id/accept", h.AcceptInvitation)
	return app
}

func teamMembersNeedsDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("team_members_test: TEST_DATABASE_URL not set — skipping integration test")
	}
	return testhelpers.SetupTestDB(t)
}

// seedMembersTeam inserts a team + a primary owner. Returns (teamID, ownerID).
func seedMembersTeam(t *testing.T, db *sql.DB) (uuid.UUID, uuid.UUID) {
	t.Helper()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	owner, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)
	return teamID, owner.ID
}

func seedMember(t *testing.T, db *sql.DB, teamID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	u, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", role)
	require.NoError(t, err)
	return u.ID
}

func miniRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func doJSON(t *testing.T, app *fiber.App, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	return resp
}

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var out map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #47 / #A5 — PATCH /api/v1/team/members/:user_id
// ─────────────────────────────────────────────────────────────────────────

func TestUpdateRole_OwnerCanPromoteMemberToAdmin(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	memberID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "admin"}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "admin", body["role"])

	role, err := models.GetUserRole(context.Background(), db, teamID, memberID)
	require.NoError(t, err)
	assert.Equal(t, "admin", role)
}

func TestUpdateRole_NonOwnerForbidden(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, _ := seedMembersTeam(t, db)
	adminID := seedMember(t, db, teamID, "admin")
	targetID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), adminID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPatch, "/api/v1/team/members/"+targetID.String(),
		map[string]string{"role": "viewer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestUpdateRole_RejectsOwnerAssignment(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	memberID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "owner"}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "cannot_assign_owner_role", body["error"])
	assert.NotEmpty(t, body["agent_action"], "agent_action must be populated on owner-assignment refusal")
}

func TestUpdateRole_RejectsUnknownRole(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	memberID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPatch, "/api/v1/team/members/"+memberID.String(),
		map[string]string{"role": "superadmin"}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "invalid_role", body["error"])
}

func TestUpdateRole_TargetNotOnTeam(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	otherTeamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	strangerID := seedMember(t, db, otherTeamID, "developer")

	resp := doJSON(t, app, http.MethodPatch, "/api/v1/team/members/"+strangerID.String(),
		map[string]string{"role": "admin"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #48 — POST /api/v1/team/members/:user_id/promote-to-primary
// ─────────────────────────────────────────────────────────────────────────

func TestPromoteToPrimary_OwnerTransfersPrimaryAtomically(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	targetID := seedMember(t, db, teamID, "admin")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPost,
		"/api/v1/team/members/"+targetID.String()+"/promote-to-primary", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, targetID.String(), body["primary_user_id"])

	var primaryCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE team_id = $1 AND is_primary = true`, teamID).Scan(&primaryCount))
	assert.Equal(t, 1, primaryCount, "exactly one primary per team")

	var targetPrimary bool
	require.NoError(t, db.QueryRow(`SELECT is_primary FROM users WHERE id = $1`, targetID).Scan(&targetPrimary))
	assert.True(t, targetPrimary, "target must be primary after promote")

	var oldRole string
	var oldPrimary bool
	require.NoError(t, db.QueryRow(`SELECT role, is_primary FROM users WHERE id = $1`, ownerID).Scan(&oldRole, &oldPrimary))
	assert.False(t, oldPrimary, "old primary must no longer be primary")
	assert.Equal(t, "admin", oldRole, "old owner is demoted to admin")

	var newRole string
	require.NoError(t, db.QueryRow(`SELECT role FROM users WHERE id = $1`, targetID).Scan(&newRole))
	assert.Equal(t, "owner", newRole)
}

func TestPromoteToPrimary_NonOwnerForbidden(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, _ := seedMembersTeam(t, db)
	adminID := seedMember(t, db, teamID, "admin")
	targetID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), adminID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPost,
		"/api/v1/team/members/"+targetID.String()+"/promote-to-primary", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestPromoteToPrimary_TargetNotOnTeam(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	otherTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	stranger := seedMember(t, db, otherTeam, "developer")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPost,
		"/api/v1/team/members/"+stranger.String()+"/promote-to-primary", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestPromoteToPrimary_IdempotentWhenAlreadyPrimary(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodPost,
		"/api/v1/team/members/"+ownerID.String()+"/promote-to-primary", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #49 / #52 — DELETE /api/v1/team/members/:user_id
// ─────────────────────────────────────────────────────────────────────────

func TestRemoveMember_RefusesPrimary(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodDelete,
		"/api/v1/team/members/"+ownerID.String(), nil, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "cannot_remove_primary", body["error"])
	agentAction, _ := body["agent_action"].(string)
	assert.Contains(t, agentAction, "promote",
		"agent_action must reference promote-to-primary as the next step")
}

func TestRemoveMember_PrimaryStillBlockedAfterRoleDemote(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)

	// Demote the primary's role to 'admin' but leave is_primary=true.
	_, err := db.Exec(`UPDATE users SET role = 'admin' WHERE id = $1`, ownerID)
	require.NoError(t, err)

	// Add a second user as owner so the requireOwner() gate passes for the
	// caller (otherwise we never get to the RemoveMember body's is_primary
	// check).
	otherOwner := seedMember(t, db, teamID, "owner")

	app := teamMembersApp(t, db, miniRedis(t), otherOwner.String(), teamID.String())
	resp := doJSON(t, app, http.MethodDelete,
		"/api/v1/team/members/"+ownerID.String(), nil, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "cannot_remove_primary", body["error"])
}

func TestRemoveMember_ReturnsOrphanTeamID(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	memberID := seedMember(t, db, teamID, "developer")

	app := teamMembersApp(t, db, miniRedis(t), ownerID.String(), teamID.String())
	resp := doJSON(t, app, http.MethodDelete,
		"/api/v1/team/members/"+memberID.String(), nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	orphanID, ok := body["orphan_team_id"].(string)
	require.True(t, ok, "orphan_team_id must be in response")
	require.NotEmpty(t, orphanID)
	orphanUUID, err := uuid.Parse(orphanID)
	require.NoError(t, err)

	var nowTeam uuid.UUID
	var nowRole string
	require.NoError(t, db.QueryRow(`SELECT team_id, role FROM users WHERE id = $1`, memberID).
		Scan(&nowTeam, &nowRole))
	assert.Equal(t, orphanUUID, nowTeam)
	assert.Equal(t, "owner", nowRole)
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #50 — seat-limit enforced on RBAC invite path
// ─────────────────────────────────────────────────────────────────────────

func TestInviteMember_SeatLimitEnforcedOnRBACPath(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	// hobby tier (member_limit per plans.yaml is small). Pad the team out
	// to the cap then attempt to invite — RBAC path must refuse.
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "hobby"))
	owner, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)

	// Resolve the configured cap and pad the team to (cap - 1) so a
	// single further invite would push it to the cap and a second one
	// would exceed it.
	reg := plans.Default()
	limit := reg.TeamMemberLimit("hobby")
	if limit < 0 {
		t.Skip("hobby tier is unlimited in this build; seat-cap test does not apply")
	}
	for i := 1; i < limit; i++ {
		_ = seedMember(t, db, teamID, "developer")
	}

	app := teamMembersApp(t, db, miniRedis(t), owner.ID.String(), teamID.String())
	// First invite — should consume the final seat and succeed.
	resp := doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"final-seat invite must succeed (at cap-1 members + 0 pending)")
	resp.Body.Close()

	// Second invite — over the cap, MUST refuse on the RBAC path.
	resp = doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	require.Equal(t, http.StatusConflict, resp.StatusCode,
		"over-cap RBAC invite must refuse (regression: RBAC path used to bypass seat cap)")
	body := decodeBody(t, resp)
	assert.Equal(t, "member_limit", body["error"])
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #55 / #Q61 — rate limit + idempotency on /team/members/invite
// ─────────────────────────────────────────────────────────────────────────

func TestInviteMember_RateLimit_10PerHour(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	rdb := miniRedis(t)

	app := teamMembersApp(t, db, rdb, ownerID.String(), teamID.String())
	for i := 0; i < 10; i++ {
		resp := doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
			map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
		require.Equal(t, http.StatusCreated, resp.StatusCode,
			"first 10 invites must succeed; failed at i=%d", i)
		resp.Body.Close()
	}
	resp := doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "rate_limit_exceeded", body["error"])
	assert.NotEmpty(t, body["agent_action"], "rate-limit response must include agent_action")
}

func TestInviteMember_IdempotencyReplay(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	rdb := miniRedis(t)

	app := teamMembersApp(t, db, rdb, ownerID.String(), teamID.String())
	inviteEmail := testhelpers.UniqueEmail(t)
	key := uuid.NewString()

	r1 := doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": inviteEmail, "role": "developer"},
		map[string]string{"Idempotency-Key": key})
	require.Equal(t, http.StatusCreated, r1.StatusCode)
	b1 := decodeBody(t, r1)
	inv1, _ := b1["invitation"].(map[string]any)
	require.NotNil(t, inv1)
	firstToken, _ := inv1["token"].(string)

	r2 := doJSON(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": inviteEmail, "role": "developer"},
		map[string]string{"Idempotency-Key": key})
	require.Equal(t, http.StatusCreated, r2.StatusCode)
	assert.Equal(t, "true", r2.Header.Get("X-Idempotent-Replay"),
		"replay must set X-Idempotent-Replay: true")
	b2 := decodeBody(t, r2)
	inv2, _ := b2["invitation"].(map[string]any)
	require.NotNil(t, inv2)
	secondToken, _ := inv2["token"].(string)
	assert.Equal(t, firstToken, secondToken,
		"idempotent replay must return the same invitation token")
}

// ─────────────────────────────────────────────────────────────────────────
// Finding #53 — AcceptInvitation silent owner-demote carries warning
// ─────────────────────────────────────────────────────────────────────────

func TestAcceptInvitation_OwnerSilentlyDemoted_CarriesWarning(t *testing.T) {
	db, cleanup := teamMembersNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedMembersTeam(t, db)
	ctx := context.Background()

	// Hand-craft an "owner" role invitation. Legacy InviteMember refuses
	// non-"member" roles, so insert directly.
	inviteEmail := testhelpers.UniqueEmail(t)
	var invID uuid.UUID
	err := db.QueryRowContext(ctx, `
		INSERT INTO team_invitations (team_id, email, role, invited_by, status)
		VALUES ($1, $2, 'owner', $3, 'pending')
		RETURNING id
	`, teamID, inviteEmail, ownerID).Scan(&invID)
	require.NoError(t, err)

	// Make a user (different team) with the same email so the
	// AcceptInvitation handler's email-mismatch guard passes.
	otherTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	invitee, err := models.CreateUser(ctx, db, otherTeam, inviteEmail, "", "", "owner")
	require.NoError(t, err)

	app := teamMembersApp(t, db, miniRedis(t), invitee.ID.String(), otherTeam.String())
	resp := doJSON(t, app, http.MethodPost,
		"/api/v1/team/invitations/"+invID.String()+"/accept", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBody(t, resp)
	assert.Equal(t, "member", body["role"], "silent demote → role lands as member")
	warning, _ := body["warning"].(string)
	require.NotEmpty(t, warning, "warning field must be populated on silent owner-demote")
	assert.True(t,
		strings.Contains(warning, "promote-to-primary") || strings.Contains(strings.ToLower(warning), "owner"),
		"warning text must reference owner / promote-to-primary path; got: %q", warning)
}
