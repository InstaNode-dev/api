package handlers_test

// usage_wall_test.go — Track U1 endpoint tests.
//
// Verifies the three contract guarantees:
//   1. Latest row inside the 24h window → returns near_wall=true with the
//      audit metadata flattened into the response.
//   2. No row (or stale row outside 24h) → returns near_wall=false with 200.
//   3. team-tier callers flow through the same audit query as every other
//      finite tier (the former unlimited-Team short-circuit was removed by
//      the 2026-06-05 strict-margin redesign).
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

// strict-80% margin redesign (2026-06-05): GetWall no longer does a team
// lookup / team-tier short-circuit (Team is finite now and has walls like
// every other tier), so the former expectTeamLookup helper was removed —
// the handler issues exactly one query (the audit_log SELECT) for all tiers.

// TestUsageWall_ReturnsLatestRowWithMetadata is the headline test: an
// 87%-storage row written by the worker shows up in the response with
// every metadata field flattened to the top level.
func TestUsageWall_ReturnsLatestRowWithMetadata(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()

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

// TestUsageWall_CacheHeadersOnEvery200Path is the registry-iterating
// regression for BUG-API-420. /api/v1/usage/wall has two distinct 200
// code paths in GetWall (no-recent-row, row-found-with-metadata) — every
// one MUST stamp the same Cache-Control and Vary headers, otherwise a
// dashboard polling the endpoint on every nav re-hits the DB on the busy
// team-scoped audit_log table. The cases table mirrors the code paths in
// usage_wall.go; adding a third path without updating this test (which
// would mean the path skips the cache header) is the bug class rule 18
// protects against.
//
// strict-80% margin redesign (2026-06-05): the former team-tier
// short-circuit path was removed (Team is finite now), so a "team_tier"
// case is kept but now asserts Team flows through the SAME audit query as
// every other finite tier — proving the short-circuit is gone.
func TestUsageWall_CacheHeadersOnEvery200Path(t *testing.T) {
	cases := []struct {
		name  string
		prime func(mock sqlmock.Sqlmock, teamID uuid.UUID)
	}{
		{
			name: "team_tier_now_queries_audit",
			prime: func(mock sqlmock.Sqlmock, teamID uuid.UUID) {
				// Team is finite — it no longer short-circuits; it hits
				// the audit_log query like any other tier.
				mock.ExpectQuery(`SELECT metadata, created_at\s+FROM audit_log`).
					WithArgs(teamID, "near_quota_wall", sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
		},
		{
			name: "no_recent_row",
			prime: func(mock sqlmock.Sqlmock, teamID uuid.UUID) {
				mock.ExpectQuery(`SELECT metadata, created_at\s+FROM audit_log`).
					WithArgs(teamID, "near_quota_wall", sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)
			},
		},
		{
			name: "row_found_with_metadata",
			prime: func(mock sqlmock.Sqlmock, teamID uuid.UUID) {
				metadata := `{"tier":"hobby","axis":"storage","service":"postgres","current":1,"limit":2,"percent_used":50}`
				mock.ExpectQuery(`SELECT metadata, created_at\s+FROM audit_log`).
					WithArgs(teamID, "near_quota_wall", sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"metadata", "created_at"}).
						AddRow(metadata, time.Now().Add(-1*time.Hour)))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			require.NoError(t, err)
			defer db.Close()

			teamID := uuid.New()
			tc.prime(mock, teamID)

			app := newUsageWallApp(t, db, teamID)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/usage/wall", nil)
			resp, err := app.Test(req, 5000)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode)
			// BUG-API-420: Cache-Control: private, max-age=30 keeps
			// per-team caching local to the browser (never a shared
			// CDN) and clamps staleness to 30s — well under the
			// dashboard's 5-min poll interval.
			assert.Equal(t, "private, max-age=30", resp.Header.Get("Cache-Control"),
				"BUG-API-420: %s path must emit Cache-Control: private, max-age=30", tc.name)
			// Vary: Authorization prevents team A's banner state from
			// being served to team B (per-team cache key).
			assert.Equal(t, "Authorization", resp.Header.Get("Vary"),
				"BUG-API-420: %s path must emit Vary: Authorization so per-team cache keys never cross teams", tc.name)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

// TestUsageWall_TeamTierFlowsThroughAuditQuery verifies the strict-80%
// margin redesign (2026-06-05): Team is no longer unlimited, so the former
// team-tier short-circuit is GONE — a team-tier caller MUST now hit the
// audit_log query like every other finite tier. The mock primes exactly
// the audit query (and no team lookup); sqlmock strict mode would fail if
// GetWall regressed back to a pre-query short-circuit (unmet audit
// expectation) or re-added the team lookup (unexpected query).
func TestUsageWall_TeamTierFlowsThroughAuditQuery(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	// Team now flows through to the audit_log query. With no recent row it
	// returns near_wall=false — but via the query, not a short-circuit.
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
