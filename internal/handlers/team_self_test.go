package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

// teamSelfTestApp wires the GET / PATCH /api/v1/team routes against a
// mocked DB + a stub auth middleware that pins team_id / user_id. The same
// pattern as TeamSummary tests so the harness is recognisable.
func teamSelfTestApp(t *testing.T, db *sql.DB, teamID uuid.UUID, writable bool) *fiber.App {
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
		c.Locals(middleware.LocalKeyTeamID, teamID.String())
		c.Locals(middleware.LocalKeyUserID, uuid.NewString())
		// RequireWritable rejects when LocalKeyReadOnly is set to true. To
		// simulate a read-only session in tests, flip the boolean.
		if !writable {
			c.Locals(middleware.LocalKeyReadOnly, true)
		}
		return c.Next()
	})
	h := handlers.NewTeamSelfHandler(db, plans.Default())
	app.Get("/api/v1/team", h.Get)
	app.Patch("/api/v1/team", middleware.RequireWritable(), h.Update)
	return app
}

func expectTeamRow(mock sqlmock.Sqlmock, teamID uuid.UUID, name string, plan string) {
	row := sqlmock.NewRows([]string{"id", "name", "plan_tier", "stripe_customer_id", "trial_ends_at", "created_at"})
	var nm sql.NullString
	if name != "" {
		nm = sql.NullString{String: name, Valid: true}
	}
	row.AddRow(teamID, nm, plan, sql.NullString{}, nil, time.Now())
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).WithArgs(teamID).WillReturnRows(row)
}

func TestTeamSelf_Get_ReturnsTeamRow(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	expectTeamRow(mock, teamID, "Acme Inc", "pro")

	app := teamSelfTestApp(t, db, teamID, true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/team", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK   bool `json:"ok"`
		Team struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			PlanTier string `json:"plan_tier"`
		} `json:"team"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, teamID.String(), body.Team.ID)
	assert.Equal(t, "Acme Inc", body.Team.Name)
	assert.Equal(t, "pro", body.Team.PlanTier)
}

func TestTeamSelf_Patch_RenamesTeam(t *testing.T) {
	teamID := uuid.New()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE teams SET name`).
		WithArgs("New Co", teamID).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectTeamRow(mock, teamID, "New Co", "pro")

	app := teamSelfTestApp(t, db, teamID, true)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team", strings.NewReader(`{"name":"New Co"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK   bool `json:"ok"`
		Team struct {
			Name string `json:"name"`
		} `json:"team"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, "New Co", body.Team.Name)
}

func TestTeamSelf_Patch_RejectsEmptyName(t *testing.T) {
	teamID := uuid.New()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	app := teamSelfTestApp(t, db, teamID, true)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team", strings.NewReader(`{"name":"   "}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestTeamSelf_Patch_RejectsOverlongName(t *testing.T) {
	teamID := uuid.New()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	app := teamSelfTestApp(t, db, teamID, true)
	body := bytes.NewReader([]byte(`{"name":"` + strings.Repeat("x", 201) + `"}`))
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestTeamSelf_Patch_BlockedByReadOnlySession(t *testing.T) {
	teamID := uuid.New()
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()
	app := teamSelfTestApp(t, db, teamID, false) // writable = false
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/team", strings.NewReader(`{"name":"Try"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestCapabilities_PublicNoAuth — agent-discovery endpoint returns the full
// tier matrix without credentials.
func TestCapabilities_PublicNoAuth(t *testing.T) {
	app := fiber.New()
	h := handlers.NewCapabilitiesHandler(plans.Default())
	app.Get("/api/v1/capabilities", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK    bool             `json:"ok"`
		Tiers []map[string]any `json:"tiers"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.GreaterOrEqual(t, len(body.Tiers), 4, "must surface at least anon/hobby/pro/team")

	// Every tier carries the discovery fields agents need.
	found := map[string]bool{}
	for _, tierObj := range body.Tiers {
		tierName, _ := tierObj["tier"].(string)
		found[tierName] = true
		_, hasStorage := tierObj["storage_limit_mb"]
		_, hasConns := tierObj["connections_limit"]
		_, hasUpgrade := tierObj["upgrade_url"]
		assert.True(t, hasStorage, "tier %v missing storage_limit_mb", tierName)
		assert.True(t, hasConns, "tier %v missing connections_limit", tierName)
		assert.True(t, hasUpgrade, "tier %v missing upgrade_url", tierName)
	}
	assert.True(t, found["anonymous"])
	assert.True(t, found["hobby"])
	assert.True(t, found["pro"])
}

// TestIncidents_PublicReturnsEmpty — the dashboard's IncidentsPage tolerates
// any shape; the api commits to {ok, items, total, status_page}.
func TestIncidents_PublicReturnsEmpty(t *testing.T) {
	app := fiber.New()
	h := handlers.NewIncidentsHandler()
	app.Get("/api/v1/incidents", h.List)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/incidents", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		OK         bool             `json:"ok"`
		Items      []map[string]any `json:"items"`
		Total      int              `json:"total"`
		StatusPage string           `json:"status_page"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Empty(t, body.Items)
	assert.Equal(t, 0, body.Total)
	assert.Contains(t, body.StatusPage, "instanode.dev/status")
}
