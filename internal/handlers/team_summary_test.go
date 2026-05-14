package handlers_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
	"instant.dev/internal/middleware"
	"instant.dev/internal/plans"
)

// expectTeamSummaryQueries primes sqlmock with the four-query sequence
// TeamSummaryHandler.computeSummary runs:
//
//	1) teams row → tier
//	2) GROUP BY resource_type             (countResourcesByType)
//	3) COUNT(*) FROM deployments          (countDeployments)
//	4) COUNT(*) FROM users WHERE team_id  (CountTeamMembers)
//	5) COUNT(DISTINCT key) FROM vault_secrets (CountVaultKeysByTeam)
func expectTeamSummaryQueries(mock sqlmock.Sqlmock, teamID uuid.UUID) {
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at",
		}).AddRow(teamID, sql.NullString{}, "pro", sql.NullString{}, time.Now()))

	// resource_type breakdown — one row per type. The handler bins each
	// row into the typed struct; unknown types fold into `other`.
	mock.ExpectQuery(`SELECT resource_type, COUNT\(\*\)`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"resource_type", "count"}).
			AddRow("postgres", 2).
			AddRow("redis", 1).
			AddRow("webhook", 3))

	// deployments count
	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM deployments`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// team members
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// vault keys
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT key\) FROM vault_secrets`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
}

func newSummaryApp(t *testing.T, db *sql.DB, rdb *redis.Client, teamID uuid.UUID) *fiber.App {
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
	h := handlers.NewTeamSummaryHandler(db, rdb, plans.Default())
	app.Get("/api/v1/team/summary", h.GetSummary)
	return app
}

// TestTeamSummary_CachedHitSkipsDBOnSecondCall — same headline guarantee
// as /billing/usage: two calls inside the 5-min window run ONE aggregation.
func TestTeamSummary_CachedHitSkipsDBOnSecondCall(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	expectTeamSummaryQueries(mock, teamID)

	app := newSummaryApp(t, db, rdb, teamID)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/team/summary", nil)
	resp, err := app.Test(req, 5000)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "private, max-age=300", resp.Header.Get("Cache-Control"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, float64(300), body["freshness_seconds"])
	assert.Equal(t, "pro", body["tier"])
	assert.NotEmpty(t, body["as_of"])

	counts, ok := body["counts"].(map[string]any)
	require.True(t, ok)
	resourcesObj := counts["resources"].(map[string]any)
	assert.Equal(t, float64(6), resourcesObj["total"], "2 postgres + 1 redis + 3 webhook = 6")
	assert.Equal(t, float64(2), resourcesObj["postgres"])
	assert.Equal(t, float64(1), resourcesObj["redis"])
	assert.Equal(t, float64(3), resourcesObj["webhook"])
	assert.Equal(t, float64(1), counts["deployments"])
	assert.Equal(t, float64(2), counts["members"])
	assert.Equal(t, float64(5), counts["vault_keys"])

	// Second call: must not touch the DB.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/team/summary", nil)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	require.NoError(t, mock.ExpectationsWereMet(), "second call must hit cache, not DB")
}

// TestTeamSummary_DifferentTeamsGetDifferentCacheEntries — team-scoped
// keys (§14 question 7). Two teams = two DB roundtrips.
func TestTeamSummary_DifferentTeamsGetDifferentCacheEntries(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamA := uuid.New()
	teamB := uuid.New()
	expectTeamSummaryQueries(mock, teamA)
	expectTeamSummaryQueries(mock, teamB)

	for _, tid := range []uuid.UUID{teamA, teamB} {
		app := newSummaryApp(t, db, rdb, tid)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/team/summary", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}
