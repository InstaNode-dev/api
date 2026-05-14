package handlers_test

// usage_wall_test.go — Track U1 endpoint tests.
//
// Verifies the three contract guarantees:
//   1. Latest row inside the 24h window → returns near_wall=true with the
//      audit metadata flattened into the response.
//   2. No row (or stale row outside 24h) → returns near_wall=false with 200.
//   3. team-tier callers always get near_wall=false without an audit query.
//
// Uses sqlmock so the tests are hermetic and don't depend on a live DB.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
)

// newUsageWallApp wires a Fiber app with the wall endpoint mounted at
// /api/v1/usage/wall, plus a no-op auth middleware that stamps team_id
// onto the request locals. Mirrors newUsageApp in billing_usage_test.go.
func newUsageWallApp(t *testing.T, db *sql.DB, teamID uuid.UUID) *fiber.App {
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
		return c.Next()
	})
	h := handlers.NewUsageWallHandler(db)
	app.Get("/api/v1/usage/wall", h.GetWall)
	return app
}

// expectTeamLookup primes the team-row SELECT used by the tier gate.
// The lookup runs first inside GetWall — every test (except the team
// tier one) wants this to return a non-team tier so the audit query
// proceeds.
func expectTeamLookup(mock sqlmock.Sqlmock, teamID uuid.UUID, tier string) {
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at",
		}).AddRow(teamID, sql.NullString{}, tier, sql.NullString{}, time.Now()))
}

// TestUsageWall_ReturnsLatestRowWithMetadata is the headline test: an
// 87%-storage row written by the worker shows up in the response with
// every metadata field flattened to the top level.
func TestUsageWall_ReturnsLatestRowWithMetadata(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	expectTeamLookup(mock, teamID, "hobby")

	createdAt := time.Now().Add(-2 * time.Hour)
	metadata := `{"tier":"hobby","axis":"storage","service":"postgres","current":471859200,"limit":536870912,"percent_used":87}`

	mock.ExpectQuery(`SELECT metadata, created_at\s+FROM audit_log`).
		WithArgs(teamID, "near_quota_wall", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"metadata", "created_at"}).
			AddRow(metadata, createdAt))

	app := newUsageWallApp(t, db, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/usage/wall", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, true, body["near_wall"])
	assert.Equal(t, "hobby", body["tier"])
	assert.Equal(t, "storage", body["axis"])
	assert.Equal(t, "postgres", body["service"])
	assert.Equal(t, float64(87), body["percent_used"])
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestUsageWall_ReturnsFalseWhenNoRecentRow covers the "absent or stale"
// branch: no audit row inside the 24h window → 200 + near_wall=false.
func TestUsageWall_ReturnsFalseWhenNoRecentRow(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	expectTeamLookup(mock, teamID, "hobby")

	mock.ExpectQuery(`SELECT metadata, created_at\s+FROM audit_log`).
		WithArgs(teamID, "near_quota_wall", sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)

	app := newUsageWallApp(t, db, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/usage/wall", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, false, body["near_wall"])
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestUsageWall_TeamTierShortCircuits verifies the team-tier early
// return: a team-tier caller MUST get near_wall=false without an
// audit_log query (sqlmock strict mode catches the unexpected query).
func TestUsageWall_TeamTierShortCircuits(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	expectTeamLookup(mock, teamID, "team")
	// NO audit_log query expected. If GetWall regresses and queries
	// audit_log for a team-tier caller, sqlmock strict mode fails the
	// test ("unexpected query").

	app := newUsageWallApp(t, db, teamID)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/usage/wall", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, false, body["near_wall"])
	require.NoError(t, mock.ExpectationsWereMet())
}
