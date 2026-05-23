package handlers_test

// status_final_test.go — FINAL coverage pass for status.go. Closes:
//   - compute per-component-read-failure fail-open arm (status.go:174-185): a
//     component lists OK but its samples query errors → emit a -1 uptime row.
//   - Get compute-error arm (status.go:135): listComponents errors → 500
//     status_failed.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// listComponents OK, but the per-component samples query errors → fail-open
// row with uptime -1, still 200.
func TestStatusFinal_ComponentReadFailure_FailOpen(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`FROM service_components`).
		WillReturnRows(sqlmock.NewRows([]string{"slug", "display_name", "category", "description"}).
			AddRow("api", "API", "core", "instanode API"))
	// The per-component samples query ERRORS → computeOne returns an error →
	// fail-open row.
	mock.ExpectQuery(`FROM uptime_samples`).
		WithArgs("api", sqlmock.AnyArg()).
		WillReturnError(assertErr2("samples read boom"))

	app := newStatusApp(t, db, rdb)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// listComponents errors → compute returns error → Get returns 500 status_failed.
func TestStatusFinal_ListComponentsError_500(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	require.NoError(t, err)
	defer db.Close()
	mock.ExpectQuery(`FROM service_components`).WillReturnError(assertErr2("components read boom"))

	app := newStatusApp(t, db, rdb)
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

type assertErr2 string

func (e assertErr2) Error() string { return string(e) }
