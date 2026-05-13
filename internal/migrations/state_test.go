package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/migrations"
)

// TestReaderHappyPath asserts that a successful DB read populates every
// State field and the status is "ok".
func TestReaderHappyPath(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("022_schema_migrations.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(22))

	r := migrations.NewReader(sqlDB, 0, nil)
	got := r.Get(t.Context())

	require.Equal(t, migrations.StatusOK, got.Status)
	require.Equal(t, "022_schema_migrations.sql", got.Filename)
	require.Equal(t, 22, got.Count)

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestReaderDBError flips status to "unknown" on a query failure and
// returns zero-valued filename/count without panicking. Importantly,
// it does NOT return the error to the caller — /healthz must stay 200 OK
// even when the tracking row read fails.
func TestReaderDBError(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnError(errors.New("connection refused"))

	r := migrations.NewReader(sqlDB, 0, nil)
	got := r.Get(t.Context())

	require.Equal(t, migrations.StatusUnknown, got.Status)
	require.Equal(t, "", got.Filename)
	require.Equal(t, 0, got.Count)
}

// TestReaderNoRows handles the edge case where the schema_migrations
// table exists but is empty (very early in a fresh-DB boot before
// RunMigrations has finished recording filenames). Status should be
// "ok" — the read succeeded — with an empty filename and zero count.
func TestReaderNoRows(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"})) // empty
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	r := migrations.NewReader(sqlDB, 0, nil)
	got := r.Get(t.Context())

	require.Equal(t, migrations.StatusOK, got.Status)
	require.Equal(t, "", got.Filename)
	require.Equal(t, 0, got.Count)
}

// TestReaderCachesWithinTTL hammers Get(ctx) many times after seeding
// the cache once and asserts only one DB roundtrip occurred. This is
// the load-shedding guarantee /healthz depends on.
func TestReaderCachesWithinTTL(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("022_schema_migrations.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(22))

	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	r := migrations.NewReader(sqlDB, 60*time.Second, clock)

	// Cold call.
	require.Equal(t, "022_schema_migrations.sql", r.Get(t.Context()).Filename)
	// 100 more calls within TTL — every one must be a cache hit.
	for i := 0; i < 100; i++ {
		now = now.Add(time.Millisecond)
		require.Equal(t, "022_schema_migrations.sql", r.Get(t.Context()).Filename)
	}

	require.NoError(t, mock.ExpectationsWereMet(),
		"only one DB roundtrip should have occurred across 101 reads")
}

// TestReaderRefreshesAfterTTL is the complement: once the TTL elapses,
// the next Get re-queries and picks up newly-applied migrations. The
// staleness window for "new deploy applied 023" is one TTL — currently
// 60s — which is the design budget.
func TestReaderRefreshesAfterTTL(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// First read: 022.
	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("022_schema_migrations.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(22))
	// Second read (post-TTL): 023.
	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("023_new_thing.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(23))

	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	r := migrations.NewReader(sqlDB, 60*time.Second, clock)

	require.Equal(t, "022_schema_migrations.sql", r.Get(t.Context()).Filename)

	// Jump past TTL.
	now = now.Add(61 * time.Second)
	require.Equal(t, "023_new_thing.sql", r.Get(t.Context()).Filename)

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestReaderNilDB is the defensive rail — a misconfigured caller that
// passes a nil DB must not panic. Status is "unknown".
func TestReaderNilDB(t *testing.T) {
	r := migrations.NewReader(nil, 0, nil)
	got := r.Get(t.Context())

	require.Equal(t, migrations.StatusUnknown, got.Status)
	require.Equal(t, "", got.Filename)
	require.Equal(t, 0, got.Count)
}
