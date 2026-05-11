package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/middleware"
)

// rbacApp builds a Fiber app that injects (userID, role) into Locals before
// passing through RequireRole. This isolates the role-check logic from JWT
// parsing — those paths are covered in auth_test.go.
func rbacApp(role, userID, requiredRole string) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(middleware.LocalKeyUserID, userID)
		if role != "" {
			c.Locals(middleware.LocalKeyTeamRole, role)
		}
		return c.Next()
	})
	app.Get("/protected", middleware.RequireRole(requiredRole), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	return app
}

func mustGet(t *testing.T, app *fiber.App, path string) *http.Response {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), 1000)
	require.NoError(t, err)
	return resp
}

// TestRBAC_Hierarchy verifies the canonical hierarchy: owner > admin > developer > viewer.
// RequireRole("developer") must allow owner/admin/developer through and block viewer.
func TestRBAC_Hierarchy(t *testing.T) {
	cases := []struct {
		actorRole string
		want      int
	}{
		{"owner", http.StatusOK},
		{"admin", http.StatusOK},
		{"developer", http.StatusOK},
		{"member", http.StatusOK}, // legacy alias for developer
		{"viewer", http.StatusForbidden},
		{"", http.StatusForbidden},
		{"bogus", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run("require_developer/"+tc.actorRole, func(t *testing.T) {
			app := rbacApp(tc.actorRole, "user-123", "developer")
			resp := mustGet(t, app, "/protected")
			defer resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

// TestRBAC_RequireAdmin only owner/admin pass.
func TestRBAC_RequireAdmin(t *testing.T) {
	cases := []struct {
		actorRole string
		want      int
	}{
		{"owner", http.StatusOK},
		{"admin", http.StatusOK},
		{"developer", http.StatusForbidden},
		{"member", http.StatusForbidden},
		{"viewer", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.actorRole, func(t *testing.T) {
			app := rbacApp(tc.actorRole, "user-x", "admin")
			resp := mustGet(t, app, "/protected")
			defer resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

// TestRBAC_RequireOwner only owner passes.
func TestRBAC_RequireOwner(t *testing.T) {
	cases := []struct {
		actorRole string
		want      int
	}{
		{"owner", http.StatusOK},
		{"admin", http.StatusForbidden},
		{"developer", http.StatusForbidden},
		{"viewer", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.actorRole, func(t *testing.T) {
			app := rbacApp(tc.actorRole, "user-x", "owner")
			resp := mustGet(t, app, "/protected")
			defer resp.Body.Close()
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

// TestRBAC_RequireViewer all four standard roles pass.
func TestRBAC_RequireViewer(t *testing.T) {
	roles := []string{"owner", "admin", "developer", "viewer", "member"}
	for _, r := range roles {
		t.Run(r, func(t *testing.T) {
			app := rbacApp(r, "user-x", "viewer")
			resp := mustGet(t, app, "/protected")
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

// TestRBAC_NoUser returns 401 unauthorized — RequireRole must run after RequireAuth.
func TestRBAC_NoUser(t *testing.T) {
	app := fiber.New()
	app.Get("/x", middleware.RequireRole("viewer"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"ok": true})
	})
	resp := mustGet(t, app, "/x")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestRBAC_GetTeamRole_Empty when no role is set Locals returns "".
func TestRBAC_GetTeamRole_Empty(t *testing.T) {
	app := fiber.New()
	var observed string
	app.Get("/x", func(c *fiber.Ctx) error {
		observed = middleware.GetTeamRole(c)
		return c.JSON(fiber.Map{"ok": true})
	})
	resp := mustGet(t, app, "/x")
	defer resp.Body.Close()
	assert.Equal(t, "", observed)
}
