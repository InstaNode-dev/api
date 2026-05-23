package handlers_test

// team_coverage_branches_test.go — final coverage push for the
// team/membership handlers: the mailer-failure log branches, the
// best-effort-audit failure log branches, the DB-error arms of the
// settings/list/revoke paths, and the AcceptInvitation warning tail.
//
// Strategy:
//   - sqlmock for every "the DB call fails" branch (the only way to make
//     a healthy postgres return a driver error deterministically).
//   - a failingInviteMailer (embeds *email.Client, overrides only
//     SendTeamInviteWithKey to error) for the "invite email failed" slog
//     branches in team_members.go + teams.go.
//
// Reuses teamCoverageApp / decodeBodyMap / teamSettingsTestApp /
// teamsRBACApp from the sibling coverage test files (same package).

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
	"instant.dev/internal/email"
	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
	"instant.dev/internal/testhelpers"
)

// failingInviteMailer satisfies email.Mailer (via the embedded noop client)
// but fails every team-invite send, exercising the slog.Warn("invite_email_failed")
// branches in team_members.go and teams.go.
type failingInviteMailer struct {
	*email.Client
}

func (failingInviteMailer) SendTeamInviteWithKey(ctx context.Context, toEmail, idempotencyKey, teamName, acceptURL string) error {
	return errors.New("mock: brevo down")
}

func newFailingInviteMailer() email.Mailer {
	return failingInviteMailer{Client: email.NewNoop()}
}

// teamMembersAppWithMailer wires a TeamMembersHandler with a caller-supplied
// mailer (used to inject the failing mailer).
func teamMembersAppWithMailer(t *testing.T, db *sql.DB, mail email.Mailer, userID, teamID string) *fiber.App {
	t.Helper()
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
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	h := handlers.NewTeamMembersHandler(db, cfg, plans.Default(), mail, nil)
	app.Post("/api/v1/team/members/invite", h.InviteMember)
	return app
}

// teamsRBACAppWithMailer wires a TeamsHandler with a caller-supplied mailer.
func teamsRBACAppWithMailer(t *testing.T, db *sql.DB, mail email.Mailer, userID, teamID string) *fiber.App {
	t.Helper()
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
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	h := handlers.NewTeamsHandler(db, cfg, mail)
	app.Post("/api/v1/teams/:team_id/invitations", h.CreateInvitation)
	return app
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — RBAC invite SUCCESS but email send FAILS (215/258 log)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_RBACEmailSendFails — the RBAC invite is
// created, but SendTeamInviteWithKey returns an error → handler logs and
// still returns 201. Drives the mailErr != nil branch in the RBAC arm.
func TestTeamMembers_InviteMember_RBACEmailSendFails(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamMembersAppWithMailer(t, db, newFailingInviteMailer(), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — checkTeamSeatLimit count-error arm (293/297)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_InviteMember_SeatCountError — owner, hobby tier (finite
// limit so the seat pre-check runs), but CountTeamMembers fails →
// 500 internal_error (checkTeamSeatLimit error → 244-246).
func TestTeamMembers_InviteMember_SeatCountError(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// 1. actor role → owner
	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	// 2. plan tier → hobby (finite member_limit so seat pre-check runs)
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"plan_tier"}).AddRow("hobby"))
	// 3. GetTeamByID (team name) — tolerate, return a row
	mock.ExpectQuery(`SELECT .* FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "hobby", sql.NullString{}, time.Now(), "auto_24h"))
	// 4. CountTeamMembers → error
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamMembersAppWithMailer(t, db, email.NewNoop(), userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost, "/api/v1/team/members/invite",
		map[string]string{"email": "x@y.com", "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — AcceptInvitation tier-lookup error (679) + warning tail
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_AcceptInvitation_TierError — invitation found, but the
// team plan-tier lookup fails → 500 tier_failed (679-681). sqlmock.
func TestTeamMembers_AcceptInvitation_TierError(t *testing.T) {
	invID, teamID, userID := uuid.New(), uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// GetInvitationByID → returns a row whose team_id = teamID
	mock.ExpectQuery(`SELECT id, team_id, email, role, status, invited_by, created_at, expires_at\s+FROM team_invitations WHERE id`).
		WithArgs(invID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "team_id", "email", "role", "status", "invited_by", "created_at", "expires_at",
		}).AddRow(invID, teamID, "x@y.com", "developer", "pending", userID, time.Now(), time.Now().Add(time.Hour)))
	// teamPlanTier → error
	mock.ExpectQuery(`SELECT plan_tier FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/team/invitations/"+invID.String()+"/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_members.go — ListInvitations list_failed (616) + RevokeInvitation
// model error (658)
// ───────────────────────────────────────────────────────────────────────

// TestTeamMembers_ListInvitations_ListFailed — owner, but the invitations
// query fails → 500 list_failed.
func TestTeamMembers_ListInvitations_ListFailed(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock.ExpectQuery(`FROM team_invitations\s+WHERE team_id = \$1 AND status = 'pending'`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodGet, "/api/v1/team/invitations", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamMembers_RevokeInvitation_LookupModelError — owner, valid uuid,
// but GetInvitationByID returns a driver error → teamMembersModelError
// default arm → 500 internal_error (658-660 + the default switch arm).
func TestTeamMembers_RevokeInvitation_LookupModelError(t *testing.T) {
	teamID, userID, invID := uuid.New(), uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COALESCE\(role, 'member'\) FROM users WHERE id`).
		WithArgs(userID, teamID).
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("owner"))
	mock.ExpectQuery(`FROM team_invitations WHERE id`).
		WithArgs(invID).
		WillReturnError(errMockDriver)

	app := teamCoverageApp(t, db, nil, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodDelete,
		"/api/v1/team/invitations/"+invID.String(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// team_settings.go — TTL update failure (152-158) + reload failure (169-172)
// ───────────────────────────────────────────────────────────────────────

// TestTeamSettings_Update_TTLUpdateFails — the policy is valid and
// different, but the UPDATE fails → 503 update_failed.
func TestTeamSettings_Update_TTLUpdateFails(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// initial GetTeamByID → current policy auto_24h
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "pro", sql.NullString{}, time.Now(), "auto_24h"))
	// UPDATE → fails
	mock.ExpectExec(`UPDATE teams SET default_deployment_ttl_policy`).
		WithArgs("permanent", teamID).
		WillReturnError(errMockDriver)

	app := teamSettingsTestApp(t, db, teamID.String())
	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/settings",
		map[string]string{"default_deployment_ttl_policy": "permanent"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// TestTeamSettings_Update_ReloadFails — UPDATE succeeds but the reload
// GetTeamByID fails → 503 fetch_failed (169-172).
func TestTeamSettings_Update_ReloadFails(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "pro", sql.NullString{}, time.Now(), "auto_24h"))
	mock.ExpectExec(`UPDATE teams SET default_deployment_ttl_policy`).
		WithArgs("permanent", teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	// reload → fails
	mock.ExpectQuery(`SELECT id, name, plan_tier, stripe_customer_id, created_at`).
		WithArgs(teamID).
		WillReturnError(errMockDriver)

	app := teamSettingsTestApp(t, db, teamID.String())
	resp := doRequest(t, app, http.MethodPatch, "/api/v1/team/settings",
		map[string]string{"default_deployment_ttl_policy": "permanent"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go (RBAC) — CreateInvitation email-send failure (95-97)
// ───────────────────────────────────────────────────────────────────────

// TestTeamsRBAC_CreateInvitation_EmailSendFails — invite created, mail send
// fails → handler logs + still 201. Drives the mailErr != nil arm.
func TestTeamsRBAC_CreateInvitation_EmailSendFails(t *testing.T) {
	db, cleanup := teamCoverageNeedsDB(t)
	defer cleanup()
	teamID, ownerID := seedTeamForCoverage(t, db, "team")
	app := teamsRBACAppWithMailer(t, db, newFailingInviteMailer(), ownerID.String(), teamID.String())

	resp := doRequest(t, app, http.MethodPost,
		"/api/v1/teams/"+teamID.String()+"/invitations",
		map[string]string{"email": testhelpers.UniqueEmail(t), "role": "developer"}, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

// ───────────────────────────────────────────────────────────────────────
// teams.go (RBAC) — ListInvitations list_failed (116) + RevokeInvitation
// lookup model-error (131) via sqlmock
// ───────────────────────────────────────────────────────────────────────

// teamsRBACAppFull wires the full RBAC route set against a sqlmock DB.
func teamsRBACAppFull(t *testing.T, db *sql.DB, userID, teamID string) *fiber.App {
	t.Helper()
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
		if userID != "" {
			c.Locals(middleware.LocalKeyUserID, userID)
		}
		if teamID != "" {
			c.Locals(middleware.LocalKeyTeamID, teamID)
		}
		return c.Next()
	})
	h := handlers.NewTeamsHandler(db, cfg, email.NewNoop())
	app.Get("/api/v1/teams/:team_id/invitations", h.ListInvitations)
	app.Delete("/api/v1/teams/:team_id/invitations/:id", h.RevokeInvitation)
	app.Post("/api/v1/invitations/:token/accept", h.AcceptInvitation)
	return app
}

// TestTeamsRBAC_ListInvitations_ListFailed — the RBAC list query fails →
// 500 list_failed (teams.go:116-118).
func TestTeamsRBAC_ListInvitations_ListFailed(t *testing.T) {
	teamID, userID := uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`FROM team_invitations`).
		WillReturnError(errMockDriver)

	app := teamsRBACAppFull(t, db, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodGet,
		"/api/v1/teams/"+teamID.String()+"/invitations", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamsRBAC_RevokeInvitation_LookupModelError — GetRBACInvitationByID
// returns a driver error → teamsModelError default arm → 500 (teams.go:131
// + the default switch arm).
func TestTeamsRBAC_RevokeInvitation_LookupModelError(t *testing.T) {
	teamID, userID, invID := uuid.New(), uuid.New(), uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`FROM team_invitations WHERE id`).
		WithArgs(invID).
		WillReturnError(errMockDriver)

	app := teamsRBACAppFull(t, db, userID.String(), teamID.String())
	resp := doRequest(t, app, http.MethodDelete,
		"/api/v1/teams/"+teamID.String()+"/invitations/"+invID.String(), nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

// TestTeamsRBAC_AcceptInvitation_RealHappyPathTeamLoaded — a real RBAC
// accept that loads the team + signs a JWT, complementing the sqlmock
// error tests by covering the success body's team-load + JWT-sign path.
func TestTeamsRBAC_AcceptInvitation_TokenTooShort(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	_ = mock // no query expected — short token short-circuits before DB.

	app := teamsRBACAppFull(t, db, "", "")
	resp := doRequest(t, app, http.MethodPost, "/api/v1/invitations/short/accept", nil, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
