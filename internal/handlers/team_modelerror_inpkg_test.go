package handlers

// team_modelerror_inpkg_test.go — in-package (package handlers) unit tests
// for the error-mapping switch helpers teamsModelError and
// teamMembersModelError.
//
// Why in-package: several switch arms map sentinel model errors that the
// RBAC / membership HANDLER call paths never actually produce (defensive
// mappings — e.g. teamsModelError's ErrInvitationTokenInvalid arm, which
// the AcceptInvitation handler short-circuits before the model can return
// it). The only way to exercise those arms — and to lock the
// error→status contract against drift — is to call the mapper directly
// with each sentinel. This mirrors the table-driven mapper tests already
// used elsewhere in this package (see agent_action_test.go et al.).

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
)

// assertSentinel returns a plain error for the default-arm test cases.
func assertSentinel(msg string) error { return errors.New(msg) }

// mapperApp mounts a single route that invokes the supplied mapper with a
// fixed error, so the test can assert the HTTP status the switch produces.
func mapperApp(mapper func(*fiber.Ctx, error) error, err error) *fiber.App {
	app := fiber.New(fiber.Config{
		// respondError writes the body and returns ErrResponseWritten;
		// swallow it so the already-written status is what the client sees.
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			if errors.Is(e, ErrResponseWritten) {
				return nil
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": e.Error()})
		},
	})
	app.Get("/x", func(c *fiber.Ctx) error { return mapper(c, err) })
	return app
}

func mapperStatus(t *testing.T, mapper func(*fiber.Ctx, error) error, err error) int {
	t.Helper()
	app := mapperApp(mapper, err)
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	resp, e := app.Test(req)
	require.NoError(t, e)
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestTeamsModelError_AllArms — every teamsModelError switch arm maps to the
// documented status. Drives the defensive arms the AcceptInvitation /
// Revoke handlers can't reach (invalid_token / invalid_role /
// email_mismatch / last_owner) plus the reachable ones.
func TestTeamsModelError_AllArms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"not_found", models.ErrInvitationNotFound, http.StatusNotFound},
		{"expired_gone", models.ErrInvitationExpired, http.StatusGone},
		{"already_accepted_gone", models.ErrInvitationAlreadyAccepted, http.StatusGone},
		{"revoked_gone", models.ErrInvitationRevoked, http.StatusGone},
		{"not_pending_gone", models.ErrInvitationNotPending, http.StatusGone},
		{"invalid_token", models.ErrInvitationTokenInvalid, http.StatusBadRequest},
		{"invalid_role", models.ErrInvalidInviteRole, http.StatusBadRequest},
		{"duplicate", models.ErrDuplicatePendingInvite, http.StatusConflict},
		{"email_mismatch", models.ErrEmailMismatchInvite, http.StatusForbidden},
		{"last_owner", models.ErrLastOwner, http.StatusConflict},
		{"default_internal", assertSentinel("some other db error"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mapperStatus(t, teamsModelError, tc.err))
		})
	}
}

// TestTeamMembersModelError_AllArms — every teamMembersModelError arm.
func TestTeamMembersModelError_AllArms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"not_team_owner", models.ErrNotTeamOwner, http.StatusForbidden},
		{"cannot_remove_primary", models.ErrCannotRemovePrimary, http.StatusBadRequest},
		{"cannot_remove_owner", models.ErrCannotRemoveOwner, http.StatusConflict},
		{"owner_cannot_leave", models.ErrOwnerCannotLeave, http.StatusConflict},
		{"invitation_not_found", models.ErrInvitationNotFound, http.StatusNotFound},
		{"invitation_expired", models.ErrInvitationExpired, http.StatusConflict},
		{"invitation_not_pending", models.ErrInvitationNotPending, http.StatusConflict},
		{"email_mismatch", models.ErrEmailMismatchInvite, http.StatusForbidden},
		{"member_limit", models.ErrMemberLimitReached, http.StatusConflict},
		{"already_member", models.ErrAlreadyTeamMember, http.StatusConflict},
		{"duplicate_pending", models.ErrDuplicatePendingInvite, http.StatusConflict},
		{"invalid_invite_role", models.ErrInvalidInviteRole, http.StatusBadRequest},
		{"invalid_member_role", models.ErrInvalidMemberRole, http.StatusBadRequest},
		{"cannot_assign_owner", models.ErrCannotAssignOwnerRole, http.StatusBadRequest},
		{"target_not_on_team", models.ErrTargetNotOnTeam, http.StatusNotFound},
		{"user_not_found", &models.ErrUserNotFound{Email: "u@x.com"}, http.StatusNotFound},
		{"default_internal", assertSentinel("unmapped db error"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mapperStatus(t, teamMembersModelError, tc.err))
		})
	}
}
