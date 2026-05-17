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

// expectUsageQueries primes a sqlmock with the exact query sequence
// BillingUsageHandler.computeUsage runs. Match strings are kept loose
// (substring expectations) so a future re-format of the SQL doesn't break
// these tests as long as the semantic shape stays the same.
//
// Order matters in sqlmock — expectations are satisfied in FIFO order.
// computeUsage runs:
//
//  1. SELECT … FROM teams WHERE id = $1                     (tierForTeam)
//     2-4) SELECT COALESCE(SUM(storage_bytes)…) (postgres, redis, mongodb)
//  5. SELECT COUNT(*) FROM deployments                      (countDeployments)
//  6. SELECT COUNT(*) FROM resources … resource_type='webhook'
//  7. SELECT COUNT(*) FROM vault_secrets                    (CountVaultKeysByTeam)
//  8. SELECT COUNT(*) FROM team_members                     (CountTeamMembers)
//
// The team_members one differs slightly across schema versions; we use
// QueryMatcherEqual=off (default) so substring matching catches both shapes.
func expectUsageQueries(mock sqlmock.Sqlmock, teamID uuid.UUID) {
	// 1) teams row → tier "hobby"
	// Wave FIX-J: GetTeamByID returns default_deployment_ttl_policy as the
	// 6th column (migration 045). The sqlmock shape must match.
	mock.ExpectQuery(`SELECT.*FROM teams WHERE id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "name", "plan_tier", "stripe_customer_id", "created_at", "default_deployment_ttl_policy",
		}).AddRow(teamID, sql.NullString{}, "hobby", sql.NullString{}, time.Now(), "auto_24h"))

	// 2-4) storage sums for postgres, redis, mongodb. Each returns 0 bytes
	// — we only care that the query fires.
	for range []string{"postgres", "redis", "mongodb"} {
		mock.ExpectQuery(`SELECT COALESCE\(SUM\(storage_bytes\)`).
			WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(int64(0)))
	}

	// 5) deployments count — P1-E: countDeployments now delegates to
	// models.CountActiveDeploymentsByTeam, whose query uses lowercase
	// count(*); regex made case-insensitive to match either form.
	mock.ExpectQuery(`(?i)SELECT count\(\*\)\s+FROM deployments`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 6) webhook resource count — CountActiveResourcesByTeamAndType
	mock.ExpectQuery(`SELECT COUNT\(\*\)\s+FROM resources`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 7) vault keys count — CountVaultKeysByTeam does
	// SELECT COUNT(DISTINCT key) FROM vault_secrets WHERE team_id = $1
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT key\) FROM vault_secrets`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	// 8) team members count — models.CountTeamMembers does `FROM users`
	// (a team is the parent table; users.team_id is the FK).
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM users WHERE team_id`).
		WithArgs(teamID).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
}

// newUsageApp wires a Fiber app with the billing-usage route mounted under
// /api/v1 with a no-op auth middleware that just stamps team_id onto the
// context. Lets the test drive the handler without minting a real JWT.
func newUsageApp(t *testing.T, db *sql.DB, rdb *redis.Client, teamID uuid.UUID) *fiber.App {
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
	h := handlers.NewBillingUsageHandler(db, rdb, plans.Default())
	app.Get("/api/v1/billing/usage", h.GetUsage)
	return app
}

// TestBillingUsage_CachedHitSkipsDBOnSecondCall — the headline §10.20
// guarantee: calling /billing/usage twice in <30s for the same team runs
// ONE DB aggregation, not two. The second call is served entirely from
// Redis. The sqlmock asserts no extra queries fire.
func TestBillingUsage_CachedHitSkipsDBOnSecondCall(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	expectUsageQueries(mock, teamID)
	// NO extra expectations — a second app.Test call must not run a single
	// new query. sqlmock's ExpectationsWereMet() fails if any extra queries
	// fire (it's strict mode).

	app := newUsageApp(t, db, rdb, teamID)

	// First call: cache miss → runs the aggregations + sets Redis.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp1, err := app.Test(req1, 5000)
	require.NoError(t, err)
	defer resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)
	assert.Equal(t, "private, max-age=30, stale-while-revalidate=60", resp1.Header.Get("Cache-Control"))

	var body1 map[string]any
	require.NoError(t, json.NewDecoder(resp1.Body).Decode(&body1))
	assert.Equal(t, true, body1["ok"])
	assert.Equal(t, float64(30), body1["freshness_seconds"])
	assert.NotEmpty(t, body1["as_of"], "as_of timestamp must be set so the UI can render 'as of Ns ago'")
	usage, ok := body1["usage"].(map[string]any)
	require.True(t, ok)
	// Every expected metric is populated.
	for _, k := range []string{"postgres", "redis", "mongodb", "deployments", "webhooks", "vault", "members"} {
		_, exists := usage[k]
		assert.True(t, exists, "usage[%s] must be present", k)
	}

	// Second call: cache hit → no DB activity.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
	resp2, err := app.Test(req2, 5000)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusOK, resp2.StatusCode)

	// sqlmock strict mode: any unexpected query would have failed the test
	// already. ExpectationsWereMet() verifies the queue is empty (no
	// expectations left unsatisfied).
	require.NoError(t, mock.ExpectationsWereMet(), "expected exactly one set of DB queries across two cached requests")
}

// TestBillingUsage_RedisDownStillServesData — with Redis unreachable, every
// request runs the aggregation but the response stays 200 + valid JSON.
// Proves the §13 fail-open contract: cache down ≠ endpoint down.
func TestBillingUsage_RedisDownStillServesData(t *testing.T) {
	// Closed port — dial fails fast.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	teamID := uuid.New()
	// Two full sets of queries — once per call, since Redis can't cache.
	expectUsageQueries(mock, teamID)
	expectUsageQueries(mock, teamID)

	app := newUsageApp(t, db, rdb, teamID)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

// TestBillingUsage_DifferentTeamsGetDifferentCacheEntries — cache keys
// scope by team_id (§14 question 7). Team A's cached value must not be
// served to team B.
func TestBillingUsage_DifferentTeamsGetDifferentCacheEntries(t *testing.T) {
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
	expectUsageQueries(mock, teamA)
	expectUsageQueries(mock, teamB)

	for _, tid := range []uuid.UUID{teamA, teamB} {
		app := newUsageApp(t, db, rdb, tid)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/usage", nil)
		resp, err := app.Test(req, 5000)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}
	require.NoError(t, mock.ExpectationsWereMet(), "each team must trigger its own aggregation")
}
