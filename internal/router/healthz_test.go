package router_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"instant.dev/common/buildinfo"
	"instant.dev/internal/db"
	"instant.dev/internal/migrations"
)

// TestHealthzShape pins the wire shape of GET /healthz. We don't spin
// up the full router (that needs Postgres + Redis + gRPC and is covered
// by the e2e suite); instead we replicate the handler verbatim from
// router.New so a future refactor that drops a field fails this test.
//
// The fields commit_id / build_time / version are the contract that
// canaries and `/instant-ship` health checks read after each deploy
// to confirm the cluster is running the pushed image. migration_version
// / migration_count / migration_status complement that with the DB-side
// signal: did the migrations apply.
func TestHealthzShape(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// Seed mock to return a known filename + count so the assertions
	// below have stable values.
	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("022_schema_migrations.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(22))

	reader := migrations.NewReader(sqlDB, 0, nil)

	app := fiber.New()
	app.Get("/healthz", func(c *fiber.Ctx) error {
		m := reader.Get(c.UserContext())
		return c.JSON(fiber.Map{
			"ok":                true,
			"service":           "instant.dev",
			"commit_id":         buildinfo.GitSHA,
			"build_time":        buildinfo.BuildTime,
			"version":           buildinfo.Version,
			"migration_version": m.PublicVersion(),
			"migration_count":   m.Count,
			"migration_status":  m.Status,
			// BUG-API-417 (QA 2026-05-29): mirror the router.go addition
			// of the live `now` server timestamp. Keeps the in-process
			// fixture aligned with prod so a future deletion of the
			// router.go emit also fails here.
			"now": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		})
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/healthz", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	// Buildinfo contract — every field is non-empty; commit_id specifically
	// falls back to "dev" when -ldflags is omitted (go run, go test).
	require.Equal(t, true, got["ok"])
	require.Equal(t, "instant.dev", got["service"])
	require.NotEmpty(t, got["commit_id"], "commit_id MUST be present on /healthz")
	require.NotEmpty(t, got["build_time"])
	require.NotEmpty(t, got["version"])

	// The compile-time defaults round-trip when no -ldflags is set —
	// this is the value canaries see in CI builds.
	require.Equal(t, buildinfo.GitSHA, got["commit_id"])
	require.Equal(t, buildinfo.BuildTime, got["build_time"])
	require.Equal(t, buildinfo.Version, got["version"])

	// BUG-API-417: `now` is the wall-clock the server emits so canaries
	// can detect clock skew between their host and the api pod without
	// an extra round trip. Format pinned to RFC 3339 with millisecond
	// precision (matches audit-log + forwarder_sent rows) and the value
	// must parse back to a time within a generous 5-second window of
	// the test's own clock (sqlmock + fiber.Test is in-process so the
	// drift is microseconds in practice).
	require.NotEmpty(t, got["now"], "BUG-API-417: /healthz must emit a server `now` timestamp so clients can detect clock skew")
	nowStr, ok := got["now"].(string)
	require.True(t, ok, "BUG-API-417: `now` must be a JSON string (RFC 3339)")
	parsedNow, parseErr := time.Parse("2006-01-02T15:04:05.000Z", nowStr)
	require.NoError(t, parseErr, "BUG-API-417: `now` must parse as `2006-01-02T15:04:05.000Z` (RFC 3339 with ms); got %q", nowStr)
	drift := time.Since(parsedNow)
	require.Less(t, drift.Abs(), 5*time.Second,
		"BUG-API-417: `now` must be within 5s of the test's wall clock (UTC); got drift=%s", drift)

	// Migration contract — new fields the canary reads to detect drift
	// between binary commit and DB schema state. BUG-API-090/217: the
	// public envelope emits the numeric prefix only ("022"), never the
	// full filename ("022_schema_migrations.sql") which would leak the
	// embedded table/feature names.
	require.Equal(t, "022", got["migration_version"])
	require.NotContains(t, got["migration_version"], "schema_migrations",
		"BUG-API-090: migration_version must not leak filename suffix to anon /healthz callers")
	require.Equal(t, float64(22), got["migration_count"]) // JSON numbers decode as float64
	require.Equal(t, "ok", got["migration_status"])

	require.NoError(t, mock.ExpectationsWereMet())
}

// TestHealthzMigrationStatusUnknownWhenDBDown asserts the DB-unreachable
// failure mode: service stays 200 OK, migration_status flips to "unknown",
// and migration_version / migration_count fall back to empty/zero. The
// contract is "/healthz should not page when the schema_migrations read
// fails — only when the service itself is broken."
func TestHealthzMigrationStatusUnknownWhenDBDown(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnError(errors.New("connection refused"))

	reader := migrations.NewReader(sqlDB, 0, nil)

	app := fiber.New()
	app.Get("/healthz", func(c *fiber.Ctx) error {
		m := reader.Get(c.UserContext())
		return c.JSON(fiber.Map{
			"ok":                true,
			"migration_version": m.PublicVersion(),
			"migration_count":   m.Count,
			"migration_status":  m.Status,
		})
	})

	resp, err := app.Test(httptest.NewRequest("GET", "/healthz", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusOK, resp.StatusCode, "service stays healthy even when migration read fails")

	body, _ := io.ReadAll(resp.Body)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))

	require.Equal(t, "unknown", got["migration_status"])
	require.Equal(t, "", got["migration_version"])
	require.Equal(t, float64(0), got["migration_count"])
}

// TestHealthzMigrationVersionStripsFilenameSuffix is the BUG-API-090/217
// regression. The pre-fix /healthz handler emitted the raw filename
// ("063_forwarder_sent_audit_link.sql") which leaks the table+feature
// names embedded in the migration to any anonymous probe. The public
// envelope now emits the numeric prefix only — canaries still get a
// drift signal, attackers don't learn the schema.
func TestHealthzMigrationVersionStripsFilenameSuffix(t *testing.T) {
	cases := []struct {
		filename string
		want     string
	}{
		{"063_forwarder_sent_audit_link.sql", "063"},
		{"022_schema_migrations.sql", "022"},
		{"001_init.sql", "001"},
		{"100_team_deletion_purge.sql", "100"},
		// No underscore — return stem only (still strips .sql).
		{"baseline.sql", "baseline"},
		// No extension — return as-is up to first underscore.
		{"063_anything", "063"},
		// Empty (DB unreachable / pre-migration) — empty out.
		{"", ""},
	}
	for _, tc := range cases {
		s := migrations.State{Filename: tc.filename}
		got := s.PublicVersion()
		require.Equal(t, tc.want, got,
			"BUG-API-090: PublicVersion(%q) must strip to numeric prefix; got %q",
			tc.filename, got)
		// Sanity rail: no underscore or .sql escapes the helper.
		require.NotContains(t, got, "_",
			"BUG-API-090: PublicVersion must never contain '_' (would leak table/feature name)")
		require.NotContains(t, got, ".sql",
			"BUG-API-090: PublicVersion must never contain '.sql' (would leak filename)")
	}
}

// TestHealthzMigrationVersionMatchesEmbeddedFile is the sanity rail —
// whatever filename the DB reports must exist in the binary's embedded
// migration set. If the running pod returns "099_phantom.sql" but no
// such file is compiled in, the deploy is broken in a way that single
// service shouldn't silently smile through.
func TestHealthzMigrationVersionMatchesEmbeddedFile(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// Pick the highest filename from the embedded set as the "DB" answer.
	// In a real deploy that's what schema_migrations would hold.
	files := db.MigrationFiles()
	require.NotEmpty(t, files, "binary must embed at least one migration")
	highest := files[len(files)-1]

	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow(highest))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(len(files)))

	reader := migrations.NewReader(sqlDB, 0, nil)
	got := reader.Get(t.Context())

	require.Equal(t, "ok", got.Status)
	require.Equal(t, highest, got.Filename)
	require.True(t, strings.HasSuffix(got.Filename, ".sql"), "filename must look like a migration file")
	require.Contains(t, files, got.Filename, "DB-reported filename must exist in the embedded migration set")
}

// TestHealthzMigrationCacheInvalidatesAfterTTL pins the cache contract:
// the first Get hits the DB, subsequent Gets within the TTL window are
// served from cache (no DB roundtrip), and the next Get after the TTL
// elapses re-queries. Clock injection avoids real-time sleeps in unit tests.
func TestHealthzMigrationCacheInvalidatesAfterTTL(t *testing.T) {
	sqlDB, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer sqlDB.Close()

	// First read: returns "021_admin_promo_codes.sql".
	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("021_admin_promo_codes.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(21))

	// Second read (after TTL): returns "022_schema_migrations.sql".
	mock.ExpectQuery(`SELECT filename FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"filename"}).AddRow("022_schema_migrations.sql"))
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM schema_migrations`).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(22))

	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	reader := migrations.NewReader(sqlDB, 60*time.Second, clock)

	// Hit 1: cold — populates the cache from the DB.
	first := reader.Get(t.Context())
	require.Equal(t, "021_admin_promo_codes.sql", first.Filename)

	// Hit 2: within the TTL — must serve from cache (no new DB call).
	// If sqlmock saw an extra query, ExpectationsWereMet() would fail later.
	now = now.Add(30 * time.Second)
	cached := reader.Get(t.Context())
	require.Equal(t, "021_admin_promo_codes.sql", cached.Filename,
		"within TTL window the cache must return the same value")

	// Hit 3: past the TTL — must refresh and pick up the new DB row.
	now = now.Add(31 * time.Second) // 61s total elapsed
	refreshed := reader.Get(t.Context())
	require.Equal(t, "022_schema_migrations.sql", refreshed.Filename,
		"after TTL elapses the cache must refresh from the DB")
	require.Equal(t, 22, refreshed.Count)

	require.NoError(t, mock.ExpectationsWereMet(),
		"the cache must have exactly two DB roundtrips (cold + post-TTL refresh)")
}
