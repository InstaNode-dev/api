package handlers_test

// team_coverage_extra_test.go — final sweep to clear teams.go and
// team_members.go past the ≥95% per-file gate.
//
// teams.go targets:
//   - RevokeInvitation requireTeamMatch failure (path team_id != auth team)
//   - AcceptInvitation session-sign failure (empty JWT secret → HMAC error)
//   - teamsModelError duplicate arm (CreateInvitation of an existing pending)
//
// team_members.go targets:
//   - replayInviteIfCached / cacheInviteResponse redis-error log branches
//     (dead Redis client during an invite with an Idempotency-Key)
//   - checkTeamSeatLimit pending-count error (sqlmock)
//   - teamMembersModelError ErrNotTeamOwner arm

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// deadRedis returns a client pointed at a port nothing listens on, so every
// command errors — used to drive the redis-error log branches.
func deadRedis(t *testing.T) *redis.Client {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// ───────────────────────────────────────────────────────────────────────
// teams.go — RevokeInvitation requireTeamMatch failure (131-133)
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_RevokeInvitation_TeamMismatch — path :team_id differs from
// the authed team → 403 forbidden via requireTeamMatch (teams.go:131-133
// is the early return of RevokeInvitation when requireTeamMatch errors).
func TestTeamsRBAC_RevokeInvitation_TeamMismatch(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	authTeam := uuid.New()
	otherTeam := uuid.New()

	app := teamsRBACAppFull(t, db, uuid.NewString(), authTeam.String())
	resp := doRequest(t, app, http.MethodDelete,
		"/api/v1/teams/"+otherTeam.String()+"/invitations/"+uuid.NewString(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go — CreateInvitation duplicate arm (teamsModelError duplicate)
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_CreateInvitation_Duplicate — inviting the same email twice
// via the RBAC create endpoint trips ErrDuplicatePendingInvite → 409
// duplicate (teamsModelError duplicate arm).
func TestTeamsRBAC_CreateInvitation_Duplicate(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamsRBACApp(t, db, ownerID.String(), teamID.String())

	dup := testhelpers.UniqueEmail(t)
	r1 := doRequest(t, app, http.MethodPost,
		"/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": dup, "role": "developer"}, nil)
	require.Equal(t, http.StatusCreated, r1.StatusCode)
	r1.Body.Close()

	r2 := doRequest(t, app, http.MethodPost,
		"/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": dup, "role": "developer"}, nil)
	defer r2.Body.Close()
	assert.Equal(t, http.StatusConflict, r2.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go — RevokeInvitation exec error (149-151) via sqlmock
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_RevokeInvitation_RevokeExecError — requireTeamMatch passes,
// the invitation is found and belongs to the team and is unaccepted, but
// the RevokeRBACInvitation UPDATE fails → teamsModelError default → 500
// (teams.go:149-151).
func TestTeamsRBAC_RevokeInvitation_RevokeExecError(t *testing.T) {
	teamID, userID, invID := uuid.New(), uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// GetRBACInvitationByID → pending, same team, not accepted
	mock.ExpectQuery(`FROM team_invitations WHERE id`).
		WithArgs(invID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "email", "role", "token", "invited_by", "expires_at", "accepted_at", "created_at",
		}).AddRow(invID, teamID, "x@y.com", "developer", "tok-xxxxxxxxxxxxxxxx", userID,
			time.Now().Add(time.Hour), nil, time.Now()))
	// RevokeRBACInvitation UPDATE → error
	mock.ExpectExec(`UPDATE team_invitations SET status = 'revoked'`).
		WithArgs(invID).
		WillReturnError(errMockDriver)

	app := teamsRBACAppFull(t, db, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodDelete,
		"/api/v1/teams/"+teamID.String()+"/invitations/"+invID.String(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — idempotency redis-error log branches (373 / 399-411)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_IdempotencyRedisError — an Idempotency-Key
// is supplied but the Redis client is dead. replayInviteIfCached logs the
// GET error and treats it as a miss; cacheInviteResponse logs the SET
// error. The invite still succeeds (201) — Redis is best-effort here.
func TestTeamMembers_InviteMember_IdempotencyRedisError(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")

	cfg := &config.Config{JWTSecret: testhelpers.TestJWTSecret, DashboardBaseURL: "http://localhost:5173"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, ownerID.String())
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		return c.Next()
	})
	h := handlers.NewTeamMembersHandler(db, cfg, plans.Default(), email.NewNoop(), deadRedis(t))
	app.Post("/api/v1/team/members/invite", h.InviteMember)

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"},
		map[string]string{"Idempotency-Key": "k-" + uuid.NewString()})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — checkTeamSeatLimit pending-count error (297-299)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_PendingCountError — owner, finite tier, the
// member COUNT succeeds but the pending-invitation COUNT fails →
// checkTeamSeatLimit errors → 500 internal_error (drives 296-299 + 244-246).
func TestTeamMembers_InviteMember_PendingCountError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"plan_tier"}).AddRow("hobby"))
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "hobby", sql.NullString{}, time.Now(), "auto_24h"))
	// CountTeamMembers → ok
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// CountPendingInvitations → error
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM team_invitations WHERE team_id`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamMembersAppWithMailer(t, db, email.NewNoop(), userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — teamMembersModelError ErrNotTeamOwner arm (700)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_LegacyNotOwner — the legacy "member" invite
// path calls models.InviteMember which returns ErrNotTeamOwner when the
// inviter is not the owner. We reach it via sqlmock: actor role lookup
// returns "owner" (so the handler's own owner/admin gate + the
// actorRole=="owner" legacy gate both pass), but the model's INNER
// GetUserRole returns a non-owner so InviteMember returns ErrNotTeamOwner,
// which teamMembersModelError maps to 403 (the 700-701 arm).
func TestTeamMembers_InviteMember_LegacyNotOwner(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// 1. handler's actor-role gate → owner (passes owner/admin + legacy gate)
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// 2. plan tier
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"plan_tier"}).AddRow("team"))
	// 3. GetTeamByID (team name)
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "team", sql.NullString{}, time.Now(), "auto_24h"))
	// 4. models.InviteMember's INNER GetUserRole → "developer" (NOT owner)
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("developer"))

	app := teamMembersAppWithMailer(t, db, email.NewNoop(), userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "member"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
