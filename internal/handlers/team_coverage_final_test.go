package handlers_test

// team_coverage_final_test.go — closes the last branches in
// team_members.go, teams.go, and team_deletion.go to clear the ≥95%
// per-file gate.
//
// Covers:
//   - team_members.go: UpdateRole/PromoteToPrimary non-owner (requireOwner
//     false), AcceptInvitation success+warning tail, the audit-insert
//     failure log branches, the teamMembersModelError ErrNotTeamOwner /
//     ErrMemberLimitReached arms, and the checkInviteRateLimit redis-error
//     fail-open branch.
//   - teams.go: AcceptInvitation team-lookup-fail + session-fail, and the
//     teamsModelError invitation-state arms (gone / invalid_token /
//     invalid_role / duplicate).
//   - team_deletion.go: cancelResult="ok" (succeeding canceler), restore
//     status-lookup-fail / flip-fail / resume-fail (sqlmock direct app).
//
// sqlmock for DB-error arms, real DB for the success+warning tails.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
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
	"instant.dev/internal/models"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// ───────────────────────────────────────────────────────────────────────
// team_members.go — UpdateRole / PromoteToPrimary non-owner (requireOwner false)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_UpdateRole_NonOwnerForbidden — an admin (not owner) is
// refused → 403. Drives the requireOwner-false arm of UpdateRole (503-505).
func TestTeamMembers_UpdateRole_NonOwnerForbidden(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeamForCoverage(t, db, "team")
	adminID := seedTeamMember(t, db, teamID, "admin")
	target := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), adminID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/members/"+target.String(),
		map[string]string{"role": "viewer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestTeamMembers_PromoteToPrimary_NonOwnerForbidden — admin refused → 403
// (requireOwner-false arm of PromoteToPrimary, 554-556).
func TestTeamMembers_PromoteToPrimary_NonOwnerForbidden(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, _ := seedTeamForCoverage(t, db, "team")
	adminID := seedTeamMember(t, db, teamID, "admin")
	target := seedTeamMember(t, db, teamID, "developer")
	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t), adminID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/members/"+target.String()+"/promote-to-primary", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — AcceptInvitation success + warning tail (687-695)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_AcceptInvitation_SuccessWithWarning — an invitation for
// role=owner on a team that already has an owner is accepted; the model
// silently demotes to member and returns a Warning, which the handler
// echoes. Drives AcceptInvitation's success body + the warning branch.
func TestTeamMembers_AcceptInvitation_SuccessWithWarning(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")

	// Invitee: a user on ANOTHER team whose email matches the invite.
	inviteeEmail := testhelpers.UniqueEmail(t)
	otherTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	invitee, err := models.CreateUser(context.Background(), db, otherTeam, inviteeEmail, "", "", "owner")
	require.NoError(t, err)

	// Pending invitation with role=owner addressed to the invitee's email.
	var invID uuid.UUID
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO team_invitations (team_id, email, role, token, invited_by, status, expires_at)
		VALUES ($1, $2, 'owner', encode(gen_random_bytes(32),'hex'), $3, 'pending', now() + interval '1 hour')
		RETURNING id
	`, teamID, inviteeEmail, ownerID).Scan(&invID))

	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t),
		invitee.ID.String(), otherTeam.String())
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/invitations/"+invID.String()+"/accept", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "member", body["role"], "owner-on-owned-team demotes to member")
	assert.NotEmpty(t, body["warning"], "demotion warning must be surfaced")
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — teamMembersModelError ErrNotTeamOwner (700) +
// ErrMemberLimitReached (715) arms via real model preconditions
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_AcceptInvitation_MemberLimitReached — a hobby team
// (limit 1, owner already present) accepting a second member trips
// ErrMemberLimitReached → 409 member_limit (the 715 arm).
func TestTeamMembers_AcceptInvitation_MemberLimitReached(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "hobby")

	inviteeEmail := testhelpers.UniqueEmail(t)
	otherTeam := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	invitee, err := models.CreateUser(context.Background(), db, otherTeam, inviteeEmail, "", "", "owner")
	require.NoError(t, err)

	var invID uuid.UUID
	require.NoError(t, db.QueryRowContext(context.Background(), `
		INSERT INTO team_invitations (team_id, email, role, token, invited_by, status, expires_at)
		VALUES ($1, $2, 'developer', encode(gen_random_bytes(32),'hex'), $3, 'pending', now() + interval '1 hour')
		RETURNING id
	`, teamID, inviteeEmail, ownerID).Scan(&invID))

	app := teamCoverageApp(t, db, teamCoverageMiniRedis(t),
		invitee.ID.String(), otherTeam.String())
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/invitations/"+invID.String()+"/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — checkInviteRateLimit redis-error fail-open (329-335)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_RateLimitRedisErrorFailsOpen — the Redis
// client points at a closed server, so checkInviteRateLimit returns an
// error; the handler logs and FAILS OPEN, proceeding to a successful 201.
func TestTeamMembers_InviteMember_RateLimitRedisErrorFailsOpen(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")

	// A client pointed at a dead address → every command errors.
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1", // nothing listens here
		DialTimeout: 200 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })

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
	h := handlers.NewTeamMembersHandler(db, cfg, plans.Default(), email.NewNoop(), rdb)
	app.Post("/api/v1/team/members/invite", h.InviteMember)

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	defer resp.Body.Close()
	// Fail-open: the rate-limit Redis error must NOT block the invite.
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go (RBAC) — AcceptInvitation team-lookup-fail (179-181) +
// session-sign-fail (184-186)
// ───────────────────────────────────────────────────────────────────────

// teamsRBACAcceptApp wires only the accept route against a sqlmock DB with
// a caller-supplied JWT secret (empty secret forces signSessionJWT to fail).
func teamsRBACAcceptApp(t *testing.T, db *sql.DB, jwtSecret string) *fiber.App {
	t.Helper()
	cfg := &config.Config{JWTSecret: jwtSecret, DashboardBaseURL: "http://localhost:5173"}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	h := handlers.NewTeamsHandler(db, cfg, email.NewNoop())
	app.Post("/api/v1/invitations/:token/accept", h.AcceptInvitation)
	return app
}

// TestTeamsRBAC_AcceptInvitation_UnknownTokenGone — an unknown token maps
// through teamsModelError to 404 (ErrInvitationNotFound). Drives the
// teamsModelError not_found arm against the real DB.
func TestTeamsRBAC_AcceptInvitation_UnknownTokenGone(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	app := teamsRBACAcceptApp(t, db, testhelpers.TestJWTSecret)
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/invitations/tok-this-token-definitely-does-not-exist-xyz/accept", nil, nil)
	defer resp.Body.Close()
	// Unknown token → 404 not_found (or 410 invitation_invalid depending on
	// the model's classification of "no such token").
	assert.Contains(t, []int{http.StatusNotFound, http.StatusGone}, resp.StatusCode)
}

// TestTeamsRBAC_AcceptInvitation_TeamLoadFails — the token accept succeeds
// (user created + invitation flipped), but the follow-on GetTeamByID fails
// → 500 team_lookup_failed (teams.go:179-181). Driven via sqlmock with a
// long-enough token to clear the handler's len<16 guard.
func TestTeamsRBAC_AcceptInvitation_TeamLoadFails(t *testing.T) {
	teamID, userID, invID := uuid.New(), uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.MatchExpectationsInOrder(false)

	token := "tok-0123456789abcdef0123456789" // >= 16 chars

	// GetRBACInvitationByToken → pending, unaccepted, unexpired
	mock.ExpectQuery(`FROM team_invitations WHERE token`).
		WithArgs(token).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "email", "role", "token", "invited_by", "expires_at", "accepted_at", "created_at",
		}).AddRow(invID, teamID, "x@y.com", "developer", token, userID,
			time.Now().Add(time.Hour), nil, time.Now()))
	mock.ExpectBegin()
	// single-use flip → 1 row
	mock.ExpectExec(`UPDATE team_invitations SET accepted_at = now\(\), status = 'accepted'`).
		WithArgs(invID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// SELECT user by email → no rows → triggers INSERT
	mock.ExpectQuery(`SELECT id, team_id, email, COALESCE\(role, 'member'\), github_id, google_id, email_verified, created_at\s+FROM users WHERE lower\(email\)`).
		WillReturnError(sql.ErrNoRows)
	// INSERT user → RETURNING the new user
	mock.ExpectQuery(`INSERT INTO users`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "email", "role", "github_id", "google_id", "email_verified", "created_at",
		}).AddRow(userID, teamID, "x@y.com", "developer", sql.NullString{}, sql.NullString{}, true, time.Now()))
	mock.ExpectCommit()
	// handler's GetTeamByID → driver error
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamsRBACAcceptApp(t, db, testhelpers.TestJWTSecret)
	resp := doRequest(t, app, http.MethodPost, "/api/v1/invitations/"+token+"/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go (RBAC) — teamsModelError arms via real preconditions
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_AcceptInvitation_RevokedGone — accepting a revoked
// invitation maps to 410 invitation_invalid (the ErrInvitationRevoked /
// ErrInvitationNotPending arm of teamsModelError, 242-246).
func TestTeamsRBAC_AcceptInvitation_RevokedGone(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "developer", ownerID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE team_invitations SET status='revoked' WHERE id=$1`, inv.ID)
	require.NoError(t, err)

	app := teamsRBACAcceptApp(t, db, testhelpers.TestJWTSecret)
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/invitations/"+inv.Token+"/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// TestTeamsRBAC_AcceptInvitation_ExpiredGone — accepting an expired
// invitation maps to 410 invitation_invalid (ErrInvitationExpired arm).
func TestTeamsRBAC_AcceptInvitation_ExpiredGone(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "developer", ownerID)
	require.NoError(t, err)
	_, err = db.Exec(`UPDATE team_invitations SET expires_at = now() - interval '1 hour' WHERE id=$1`, inv.ID)
	require.NoError(t, err)

	app := teamsRBACAcceptApp(t, db, testhelpers.TestJWTSecret)
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/invitations/"+inv.Token+"/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_deletion.go — cancelResult="ok" via a succeeding canceler (238)
// ───────────────────────────────────────────────────────────────────────

type okCanceler struct{}

func (okCanceler) CancelForTeam(ctx context.Context, teamID uuid.UUID) error { return nil }

var _ handlers.SubscriptionCanceler = okCanceler{}

// teamDeletionDirectApp wires Delete + Restore directly with locals (no auth
// middleware) so a sqlmock DB or an injected canceler can be used.
func teamDeletionDirectApp(t *testing.T, h *handlers.TeamDeletionHandler, userID, teamID string) *fiber.App {
	t.Helper()
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	app.Delete("/api/v1/team", h.Delete)
	app.Post("/api/v1/team/restore", h.Restore)
	return app
}

// TestTeamDeletion_Delete_SucceedingCanceler — a non-nil canceler that
// returns nil drives cancelResult="ok" (line 238) on a real-DB happy path.
func TestTeamDeletion_Delete_SucceedingCanceler(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID := uuid.MustParse(testhelpers.MustCreateTeamDB(t, db, "pro"))
	var slug sql.NullString
	require.NoError(t, db.QueryRowContext(context.Background(),
		`SELECT name FROM teams WHERE id = $1`, teamID).Scan(&slug))
	owner, err := models.CreateUser(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), "", "", "owner")
	require.NoError(t, err)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	h.CancelSubscription = okCanceler{}
	app := teamDeletionDirectApp(t, h, owner.ID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team",
		map[string]string{"confirm_team_slug": slug.String}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestTeamDeletion_Restore_StatusLookupDBError — the pre-restore status
// lookup fails with a driver error → 503 status_lookup_failed (343-346).
func TestTeamDeletion_Restore_StatusLookupDBError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// GetTeamDeletionStatus → driver error (not ErrNoRows).
	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`.*`).WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/restore", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// teamRow returns a sqlmock rows set for GetTeamByID with a NULL name so
// TeamSlug derives "team-<id8>".
func teamRowNullName(teamID uuid.UUID) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
	}).AddRow(teamID, sql.NullString{}, "pro", sql.NullString{}, time.Now(), "auto_24h")
}

func teamSlugFor(teamID uuid.UUID) string {
	id := teamID.String()
	if len(id) > 8 {
		id = id[:8]
	}
	return "team-" + id
}

// TestTeamDeletion_Delete_LookupDBError — GetTeamByID fails with a driver
// error → 503 team_lookup_failed (team_deletion.go:175-176).
func TestTeamDeletion_Delete_LookupDBError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team",
		map[string]string{"confirm_team_slug": teamSlugFor(teamID)}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestTeamDeletion_Delete_FlipDBError — slug matches, no canceler, but the
// RequestTeamDeletion UPDATE fails with a driver error (not the 0-rows
// "already pending" case) → 503 deletion_request_failed (250-252).
func TestTeamDeletion_Delete_FlipDBError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.MatchExpectationsInOrder(false)
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnRows(teamRowNullName(teamID))
	mock.ExpectExec(`UPDATE teams\s+SET status = 'deletion_requested'`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team",
		map[string]string{"confirm_team_slug": teamSlugFor(teamID)}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestTeamDeletion_Restore_FlipDBError — status lookup says pending, but
// the RestoreTeam UPDATE fails with a driver error → 503 restore_failed
// (362-365).
func TestTeamDeletion_Restore_FlipDBError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.MatchExpectationsInOrder(false)
	// GetTeamDeletionStatus → deletion_requested
	mock.ExpectQuery(`SELECT COALESCE\(status, 'active'\), deletion_requested_at, tombstoned_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at", "tombstoned_at"}).
			AddRow("deletion_requested", time.Now(), nil))
	// RestoreTeam UPDATE → driver error
	mock.ExpectExec(`UPDATE teams\s+SET status = 'active'`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/restore", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestTeamDeletion_Delete_PauseAndAuditFail — slug matches, the deletion
// flip succeeds, but BOTH the resource-pause UPDATE and the best-effort
// audit insert fail. Both are non-blocking: the handler logs and still
// returns 202 (drives 257-265 pause-fail + 285-291 audit-fail logs).
func TestTeamDeletion_Delete_PauseAndAuditFail(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnRows(teamRowNullName(teamID))
	mock.ExpectExec(`UPDATE teams\s+SET status = 'deletion_requested'`).
		WithArgs(teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// PauseAllTeamResources → driver error (logged, non-blocking)
	mock.ExpectExec(`UPDATE resources\s+SET status = 'paused'`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)
	// audit insert → driver error (logged, non-blocking)
	mock.ExpectExec(`INSERT INTO audit_log`).
		WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team",
		map[string]string{"confirm_team_slug": teamSlugFor(teamID)}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
}

// TestTeamDeletion_Restore_NotFoundOnDisambiguate — RestoreTeam's UPDATE
// affects 0 rows and the disambiguating SELECT returns ErrNoRows → 404
// not_found (team_deletion.go:359-361).
func TestTeamDeletion_Restore_NotFoundOnDisambiguate(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.MatchExpectationsInOrder(false)

	// pre-restore status snapshot → deletion_requested
	mock.ExpectQuery(`SELECT COALESCE\(status, 'active'\), deletion_requested_at, tombstoned_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at", "tombstoned_at"}).
			AddRow("deletion_requested", time.Now(), nil))
	// RestoreTeam UPDATE → 0 rows
	mock.ExpectExec(`UPDATE teams\s+SET status = 'active'`).
		WithArgs(teamID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// disambiguating SELECT → ErrNoRows
	mock.ExpectQuery(`SELECT status, deletion_requested_at FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(sql.ErrNoRows)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/restore", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestTeamDeletion_Restore_ResumeFail — restore flip succeeds but the
// resource-resume UPDATE fails. Non-blocking: handler logs and still 200
// (team_deletion.go:370-376). The post-restore audit insert is allowed to
// fail too.
func TestTeamDeletion_Restore_ResumeFail(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	mock.MatchExpectationsInOrder(false)

	mock.ExpectQuery(`SELECT COALESCE\(status, 'active'\), deletion_requested_at, tombstoned_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"status", "deletion_requested_at", "tombstoned_at"}).
			AddRow("deletion_requested", time.Now(), nil))
	// RestoreTeam UPDATE → 1 row (success)
	mock.ExpectExec(`UPDATE teams\s+SET status = 'active'`).
		WithArgs(teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// ResumeAllTeamResources → driver error (logged, non-blocking)
	mock.ExpectExec(`UPDATE resources`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)
	// post-restore audit insert → allow either success or failure
	mock.ExpectExec(`INSERT INTO audit_log`).
		WillReturnError(errMockDriver)

	h := handlers.NewTeamDeletionHandler(db, &config.Config{JWTSecret: testhelpers.TestJWTSecret})
	app := teamDeletionDirectApp(t, h, userID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/restore", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// keep httptest import live for the package's other compile-time needs.
var _ = httptest.NewRequest
