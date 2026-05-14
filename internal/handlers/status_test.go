// status_test.go — GET /api/v1/status.
//
// Two flavours of test live here:
//
//  1. Shape + public-access tests: no DB calls, just exercise the
//     wire contract via sqlmock seeded with a couple of components and
//     a handful of samples.
//  2. Cache contract: a second hit inside the 60s window MUST NOT
//     touch the DB. This is the same invariant the team_summary tests
//     enforce — without it a status page during an incident would
//     hammer the platform DB precisely when it's least healthy.

package handlers_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/handlers"
)

// expectStatusQueries primes sqlmock for one full status compute.
//
//	1) list components — returns api + marketing.
//	2) per-component SELECT samples — one row each for the api row,
//	   no rows for the marketing row (exercises the "no data" branch).
func expectStatusQueries(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`FROM service_components`).
		WillReturnRows(sqlmock.NewRows([]string{"slug", "display_name", "category", "description"}).
			AddRow("api", "API", "core", "instanode API").
			AddRow("marketing", "Marketing", "edge", "instanode.dev marketing site"))

	mock.ExpectQuery(`FROM uptime_samples`).
		WithArgs("api", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"sampled_at", "healthy"}).
			AddRow(time.Now().UTC().Add(-2*time.Minute), true).
			AddRow(time.Now().UTC().Add(-1*time.Minute), true))

	mock.ExpectQuery(`FROM uptime_samples`).
		WithArgs("marketing", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"sampled_at", "healthy"}))
}

// newStatusApp wires the handler with the supplied DB + Redis and
// returns a Fiber app pre-routed at /api/v1/status. Public route — no
// auth middleware.
func newStatusApp(t *testing.T, db *sql.DB, rdb *redis.Client) *fiber.App {
	t.Helper()
	app := fiber.New()
	h := handlers.NewStatusHandler(db, rdb)
	app.Get("/api/v1/status", h.Get)
	return app
}

// TestStatus_PublicShapeNoAuth — verifies the wire contract and that
// the endpoint is public (no Authorization header sent).
func TestStatus_PublicShapeNoAuth(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	expectStatusQueries(mock)

	app := newStatusApp(t, db, rdb)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK               bool                     `json:"ok"`
		FreshnessSeconds int                      `json:"freshness_seconds"`
		AsOf             string                   `json:"as_of"`
		Components       []map[string]any         `json:"components"`
		CurrentIncidents []map[string]any         `json:"current_incidents"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Equal(t, 60, body.FreshnessSeconds)
	assert.NotEmpty(t, body.AsOf)
	assert.NotNil(t, body.CurrentIncidents, "current_incidents must be present (empty list ok)")
	assert.Empty(t, body.CurrentIncidents, "incident feed not yet shipping")
	require.Len(t, body.Components, 2)

	// Every component carries the agreed-upon fields.
	for _, comp := range body.Components {
		assert.NotEmpty(t, comp["slug"])
		assert.NotEmpty(t, comp["name"])
		assert.NotEmpty(t, comp["category"])
		assert.Contains(t, []any{"operational", "degraded", "down"}, comp["current_status"])
		samples, ok := comp["last_24h_samples"].([]any)
		require.True(t, ok, "last_24h_samples must be []bool")
		assert.Equal(t, 96, len(samples), "must publish exactly 96 15-min slots = 24h")
	}

	// Cache-Control reflects the TTL so browsers don't poll faster
	// than we can serve.
	cc := resp.Header.Get("Cache-Control")
	assert.Contains(t, cc, "max-age=60")
}

// TestStatus_CachedHitSkipsDB — second call inside the 60s window must
// NOT re-query. This is the headline production guarantee: a viral
// incident driving 100k browsers at /status hits the DB once a minute,
// not 100k times a minute.
func TestStatus_CachedHitSkipsDB(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	expectStatusQueries(mock)

	app := newStatusApp(t, db, rdb)

	// First call — populates the cache.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	resp1, err := app.Test(req1)
	require.NoError(t, err)
	resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second call — must be served from cache. NOT priming any more
	// sqlmock expectations is the assertion: if it tried to touch the
	// DB, sqlmock would error.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	resp2, err := app.Test(req2)
	require.NoError(t, err)
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	require.NoError(t, mock.ExpectationsWereMet(), "second call must not run DB queries")
}

// TestStatus_NoComponents — fresh DB (post-migration, no probes yet)
// returns ok=true with an empty components list. Avoids the failure
// mode where the page 500s before the worker has ever run.
func TestStatus_NoComponents(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`FROM service_components`).
		WillReturnRows(sqlmock.NewRows([]string{"slug", "display_name", "category", "description"}))

	app := newStatusApp(t, db, rdb)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body struct {
		OK         bool             `json:"ok"`
		Components []map[string]any `json:"components"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.True(t, body.OK)
	assert.Empty(t, body.Components)
}
