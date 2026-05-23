package handlers_test

// team_coverage_mock_test.go — sqlmock-driven coverage for the
// team/membership handler branches that only fire on a DB error or on a
// schema state the real test DB can't easily produce.
//
// Why sqlmock and not the real DB:
//   - The error-log arms (ListMembers list_failed, tier_failed,
//     requireOwner role-lookup error, InviteMember role-lookup error,
//     seat-check error) require the DB call to FAIL. Against a healthy
//     postgres they never fire. sqlmock lets us return a driver error
//     deterministically.
//   - The legacy "member" invite SUCCESS body is unreachable on the real
//     test schema (team_invitations.token is NOT NULL with no default and
//     models.InviteMember's INSERT omits it — a model/schema mismatch
//     outside this handler's scope). sqlmock returns the RETURNING row so
//     the handler's success tail (response shape + audit + idempotency
//     cache) is exercised.
//
// Reuses teamCoverageApp / decodeBodyMap from team_coverage_push_test.go
// (same package). A nil Redis client is passed where the idempotency /
// rate-limit stage is not under test.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/config"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/models"
	"instant.dev/internal/testhelpers"
)

var errMockDriver = errors.New("mock: driver exploded")

// teamsRBACAppNilMail wires a TeamsHandler with a NIL mailer so the
// email-stub log branch (teams.go else arm) is exercised on invite create.
func teamsRBACAppNilMail(t *testing.T, db *sql.DB, actorUserID, actorTeamID string) *fiber.App {
	t.Helper()
	cfg := &config.Config{
		JWTSecret:        testhelpers.TestJWTSecret,
		DashboardBaseURL: "http://localhost:5173",
	}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if errors.Is(err, handlers.ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"ok": false, "error": err.Error()})
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
	h := handlers.NewTeamsHandler(db, cfg, nil) // nil mailer → stub-log branch
	app.Post("/api/v1/teams/:team_id/invitations", h.CreateInvitation)
	app.Delete("/api/v1/teams/:team_id/invitations/:id", h.RevokeInvitation)
	return app
}

// mustCreateRBACInvitationCov creates an RBAC invitation row and returns its id.
func mustCreateRBACInvitationCov(t *testing.T, db *sql.DB, teamID, inviterID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	inv, err := models.CreateRBACInvitation(context.Background(), db, teamID,
		testhelpers.UniqueEmail(t), role, inviterID)
	require.NoError(t, err)
	return inv.ID
}

// ───────────────────────────────────────────────────────────────────────
// ListMembers — DB-error arms
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_ListMembers_ListFailed — GetUserRole succeeds (owner),
// ListTeamMembers fails → 500 list_failed.
func TestTeamMembers_ListMembers_ListFailed(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// 1. GetUserRole → "owner"
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// 2. ListTeamMembers → error
	mock.ExpectQuery(`SELECT id, email, COALESCE\(role, 'member'\), created_at`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodGet, "/api/v1/team/members", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamMembers_ListMembers_TierFailed — list succeeds, the plan-tier
// lookup fails → 500 tier_failed.
func TestTeamMembers_ListMembers_TierFailed(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("admin"))
	mock.ExpectQuery(`SELECT id, email, COALESCE\(role, 'member'\), created_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "role", "created_at"}).
			AddRow(userID, "a@b.com", "admin", time.Now()))
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodGet, "/api/v1/team/members", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamMembers_ListMembers_RoleLookupError — GetUserRole returns a
// driver error (not ErrNoRows) → handler treats role=="" and 403.
func TestTeamMembers_ListMembers_RoleLookupError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodGet, "/api/v1/team/members", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// InviteMember — role-lookup error + legacy-member success tail
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_RoleLookupError — the actor-role lookup
// fails with a driver error → 500 internal_error (the slog.Error +
// respondError arm, distinct from the role=="" → 403 path).
func TestTeamMembers_InviteMember_RoleLookupError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// No Redis → skips idempotency + rate-limit. First DB hit is GetUserRole.
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamMembers_InviteMember_TierFailed — actor is owner, but the
// plan-tier lookup fails → 500 tier_failed.
func TestTeamMembers_InviteMember_TierFailed(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamMembers_InviteMember_LegacyMemberSuccess — drives the legacy
// "member" invite SUCCESS tail (response body + audit insert) that the
// real schema can't reach (token NOT NULL). sqlmock returns the
// RETURNING row from models.InviteMember and accepts the best-effort
// audit insert.
func TestTeamMembers_InviteMember_LegacyMemberSuccess(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// 1. actor role lookup → owner
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// 2. plan tier
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"plan_tier"}).AddRow("team"))
	// 3. GetTeamByID (for team name) — tolerate any shape; return a name.
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{String: "Acme", Valid: true}, "team", sql.NullString{}, time.Now(), "auto_24h"))
	// 4. models.InviteMember: GetUserRole(inviter) → owner
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// 5. withinMemberLimit — team tier is unlimited (limit<0) so the model
	//    skips the count query; but to be robust we allow an optional count.
	//    The "team" tier member_limit is unlimited (-1) so withinMemberLimit
	//    returns early without querying. Next is the existing-member COUNT.
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id = \$1 AND lower\(email\)`).
		WithArgs(teamID, sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	// 6. INSERT ... RETURNING the invitation row
	invID := uuid.New()
	mock.ExpectQuery(`INSERT INTO team_invitations`).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "email", "role", "status", "invited_by", "created_at", "expires_at",
		}).AddRow(invID, teamID, "x@y.com", "member", "pending", userID, time.Now(), time.Now().Add(7*24*time.Hour)))
	// 7. best-effort audit insert — accept any exec.
	mock.ExpectExec(`INSERT INTO audit_log`).WillReturnResult(sqlmock.NewResult(1, 1))

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "member"}, nil)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decodeBodyMap(t, resp)
	assert.Equal(t, true, body["ok"])
	inv, _ := body["invitation"].(map[string]any)
	require.NotNil(t, inv)
	assert.Equal(t, "member", inv["role"])
}

// ───────────────────────────────────────────────────────────────────────
// RemoveMember / UpdateRole / PromoteToPrimary — requireOwner DB-error arm
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_RemoveMember_RequireOwnerDBError — requireOwner's
// GetUserRole returns a driver error → requireOwner returns false → 403.
// Drives the slog.Error("team_members.role_lookup") branch.
func TestTeamMembers_RemoveMember_RequireOwnerDBError(t *testing.T) {
	teamID, actorID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(actorID, teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, actorID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodDelete, "/api/v1/team/members/"+uuid.NewString(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go (RBAC) — RevokeInvitation already-accepted (410) + CreateInvitation
// email-stub branch (mail==nil)
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_CreateInvitation_NilMailerStubLog — a TeamsHandler with a
// nil mailer takes the email-stub log branch instead of sending. Drives
// teams.go:98-100 (the else arm of the `if h.mail != nil`).
func TestTeamsRBAC_CreateInvitation_NilMailerStubLog(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")

	app := teamsRBACAppNilMail(t, db, ownerID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": "stub-" + uuid.NewString() + "@x.com", "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// TestTeamsRBAC_RevokeInvitation_AlreadyAccepted — revoking an
// already-accepted RBAC invitation → 410 already_accepted (teams.go:146-148).
func TestTeamsRBAC_RevokeInvitation_AlreadyAccepted(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")

	// Create an RBAC invitation, then mark it accepted directly.
	inv := mustCreateRBACInvitationCov(t, db, teamID, ownerID, "developer")
	_, err := db.Exec(`UPDATE team_invitations SET status='accepted', accepted_at=now() WHERE id=$1`, inv)
	require.NoError(t, err)

	app := teamsRBACApp(t, db, ownerID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodDelete,
		"/api/v1/teams/"+teamID.String()+"/invitations/"+inv.String(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusGone, resp.StatusCode)
}
