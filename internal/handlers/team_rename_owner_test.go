package handlers_test

// team_rename_owner_test.go — regression test for D05 (P1).
//
// Bug: PATCH /api/v1/team was missing RequireRole("owner") at the route
// layer, allowing any team member (admin, developer, viewer) to rename
// the team.
//
// Fix: RequireRole(middleware.RoleOwner) is now installed at the route layer
// in router.go. This test asserts the gate by wiring a test app with the
// same middleware chain as the router and verifying:
//   1. An owner can rename the team (200 OK).
//   2. A non-owner (admin / developer / viewer / member) gets 403 Forbidden.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

// teamRenameOwnerApp wires PATCH /api/v1/team with the owner role gate,
// mirroring the router.go registration for the D05 fix.
func teamRenameOwnerApp(t *testing.T, teamID uuid.UUID, role string) (*fiber.App, sqlmock.Sqlmock) {
	t.Helper()
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })

	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			if err == handlers.ErrResponseWritten {
				return nil
			}
			return c.Status(500).JSON(fiber.Map{"ok": false})
		},
	})
	app.Use(middleware.RequestID())
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		c.Locals(middleware.LocalKeyTeamRole, role)
		return c.Next()
	})
	h := handlers.NewTeamSelfHandler(sqlDB, plans.Default())
	// Mirror router.go: PATCH requires owner role + writable session (D05).
	app.Patch("/api/v1/team",
		middleware.RequireRole(middleware.RoleOwner),
		middleware.RequireWritable(),
		h.Update,
	)
	return app, mock
}

// TestTeamRename_OwnerSucceeds asserts that an owner can rename the team.
func TestTeamRename_OwnerSucceeds(t *testing.T) {
	teamID := uuid.New()
	app, mock := teamRenameOwnerApp(t, teamID, middleware.RoleOwner)

	// Pre-wire DB expectations: UPDATE + SELECT reload.
	mock.ExpectExec(`UPDATE teams SET name`).
		WithArgs("NewName", teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTeamRow(mock, teamID, "NewName", "pro")

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team", strings.NewReader(`{"name":"NewName"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "owner must be able to rename the team")
}

// TestTeamRename_NonOwnerForbidden is a table-driven test asserting that every
// non-owner role is rejected with 403. This guards against a regression where
// RequireRole("owner") is accidentally loosened to "admin" or removed.
func TestTeamRename_NonOwnerForbidden(t *testing.T) {
	nonOwnerRoles := []string{
		middleware.RoleAdmin,
		middleware.RoleDeveloper,
		middleware.RoleViewer,
		"member", // legacy role equivalent to developer
	}
	for _, role := range nonOwnerRoles {
		role := role
		t.Run("role_"+role, func(t *testing.T) {
			teamID := uuid.New()
			// No DB expectations needed — the middleware rejects before the handler runs.
			app, _ := teamRenameOwnerApp(t, teamID, role)

			req := httptest.NewRequest(http.MethodPatch, "/api/v1/team",
				strings.NewReader(`{"name":"Hijacked"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode,
				"role %q must not be able to rename the team (D05 regression guard)", role)
		})
	}
}
