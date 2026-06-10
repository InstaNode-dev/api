// Package db: coverage tests for the migration runner + connect helpers.
//
// Rule-22 coverage block — symptom: api/internal/db migration runner +
// connect entry points are the platform-DB boot gate. Enumeration: every
// exported symbol in postgres.go + redis.go.
//
//	RunMigrations, embeddedMigrationFilenames, MigrationFiles,
//	ErrDBConnect.{Error,Unwrap}, ConnectPostgres,
//	ErrRedisConnect.{Error,Unwrap}, ConnectRedis.
//
// Sites touched: all of the above. Coverage test: this file.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// testDSN returns the test postgres DSN. Mirrors testhelpers.defaultTestDBURL
// without importing testhelpers (which would create a dependency cycle:
// testhelpers imports internal/handlers which imports back into common
// stacks). Override via TEST_DATABASE_URL.
func testDSN() string {
	if v := os.Getenv("TEST_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://postgres:postgres@localhost:5432/instant_dev_test?sslmode=disable"
}

// freshTestDB creates an isolated per-test Postgres database to avoid
// colliding with the shared `instant_dev_test` schema. The migration runner
// is destructive on schema_migrations rows and side-effecting on every
// table, so a unit test that exercises RunMigrations end-to-end MUST run
// against its own DB. Each test DB is dropped on cleanup.
func freshTestDB(t *testing.T) (string, func()) {
	t.Helper()

	adminDSN := testDSN()
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		admin.Close()
		t.Skipf("postgres ping failed: %v", err)
	}

	dbName := fmt.Sprintf("db_runner_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + dbName); err != nil {
		admin.Close()
		t.Fatalf("CREATE DATABASE %s: %v", dbName, err)
	}
	admin.Close()

	// build the new DSN by swapping the dbname in the URL
	newDSN := swapDBName(adminDSN, dbName)
	cleanup := func() {
		a, err := sql.Open("postgres", adminDSN)
		if err != nil {
			return
		}
		defer a.Close()
		// terminate stragglers, then drop
		_, _ = a.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, dbName)
		_, _ = a.Exec("DROP DATABASE IF EXISTS " + dbName)
	}
	return newDSN, cleanup
}

// swapDBName replaces the trailing /<dbname>?... segment in a postgres URL.
func swapDBName(dsn, newName string) string {
	// find the last '/' before any '?'
	qIdx := strings.Index(dsn, "?")
	pathPart := dsn
	query := ""
	if qIdx >= 0 {
		pathPart = dsn[:qIdx]
		query = dsn[qIdx:]
	}
	slash := strings.LastIndex(pathPart, "/")
	if slash < 0 {
		return dsn // unparseable — leave alone, test will fail downstream
	}
	return pathPart[:slash+1] + newName + query
}

// TestMigrationFiles_NonEmptyAndSorted asserts the embedded filename
// list is populated and lex-sorted. The runner relies on sort order
// for deterministic application; a future change that breaks ordering
// (e.g. switching to map iteration) would re-introduce the historical
// "024 ran before 023" bug.
func TestMigrationFiles_NonEmptyAndSorted(t *testing.T) {
	files := MigrationFiles()
	if len(files) == 0 {
		t.Fatal("MigrationFiles: returned empty slice — embed.FS pattern broken")
	}
	for i := 1; i < len(files); i++ {
		if files[i-1] >= files[i] {
			t.Errorf("MigrationFiles: not sorted at index %d: %q >= %q", i, files[i-1], files[i])
		}
	}
	// sanity: every entry ends in .sql
	for _, f := range files {
		if !strings.HasSuffix(f, ".sql") {
			t.Errorf("MigrationFiles: non-.sql entry: %q", f)
		}
	}
}

// TestEmbeddedMigrationFilenames_DirectCall covers the unexported helper
// in case a future refactor changes MigrationFiles() to not call it.
func TestEmbeddedMigrationFilenames_DirectCall(t *testing.T) {
	files, err := embeddedMigrationFilenames()
	if err != nil {
		t.Fatalf("embeddedMigrationFilenames: %v", err)
	}
	if len(files) < 10 {
		t.Errorf("expected ≥10 migrations, got %d", len(files))
	}
}

// TestRunMigrations_AppliesAllAndRecordsRows runs the migration runner
// against a fresh DB, then verifies:
//  1. it returns nil (apply branch).
//  2. every embedded filename ends up in schema_migrations (record branch).
//  3. the highest filename matches the lex-max of the embed.FS — what
//     /healthz reports as migration_version.
func TestRunMigrations_AppliesAllAndRecordsRows(t *testing.T) {
	dsn, cleanup := freshTestDB(t)
	defer cleanup()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations (first apply): %v", err)
	}

	files := MigrationFiles()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != len(files) {
		t.Errorf("schema_migrations row count: want %d, got %d", len(files), count)
	}

	var maxFile string
	if err := db.QueryRow("SELECT filename FROM schema_migrations ORDER BY filename DESC LIMIT 1").Scan(&maxFile); err != nil {
		t.Fatalf("max filename: %v", err)
	}
	if maxFile != files[len(files)-1] {
		t.Errorf("max filename: want %q, got %q", files[len(files)-1], maxFile)
	}
}

// TestRunMigrations_Idempotent re-runs the runner on an already-migrated
// DB. The CREATE TABLE IF NOT EXISTS / ADD COLUMN IF NOT EXISTS / ON CONFLICT
// DO NOTHING guards must all hold; a second invocation should leave the
// schema_migrations row count exactly equal to the first run.
func TestRunMigrations_Idempotent(t *testing.T) {
	dsn, cleanup := freshTestDB(t)
	defer cleanup()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations (first): %v", err)
	}
	var first int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&first); err != nil {
		t.Fatalf("first count: %v", err)
	}

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations (second): %v", err)
	}
	var second int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&second); err != nil {
		t.Fatalf("second count: %v", err)
	}
	if first != second {
		t.Errorf("idempotency broken: first=%d second=%d", first, second)
	}
}

// TestRunMigrations_PreservesAppliedAt — re-running the runner must not
// move applied_at. The ON CONFLICT DO NOTHING clause guards this; a
// regression to ON CONFLICT DO UPDATE would mask history.
func TestRunMigrations_PreservesAppliedAt(t *testing.T) {
	dsn, cleanup := freshTestDB(t)
	defer cleanup()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations (first): %v", err)
	}

	var firstStamp time.Time
	const probe = "022_schema_migrations.sql"
	if err := db.QueryRow("SELECT applied_at FROM schema_migrations WHERE filename=$1", probe).Scan(&firstStamp); err != nil {
		t.Fatalf("read first applied_at: %v", err)
	}

	// Sleep just long enough that a re-update would produce a different stamp
	time.Sleep(50 * time.Millisecond)

	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations (second): %v", err)
	}

	var secondStamp time.Time
	if err := db.QueryRow("SELECT applied_at FROM schema_migrations WHERE filename=$1", probe).Scan(&secondStamp); err != nil {
		t.Fatalf("read second applied_at: %v", err)
	}
	if !firstStamp.Equal(secondStamp) {
		t.Errorf("applied_at moved: first=%v second=%v — ON CONFLICT branch broken", firstStamp, secondStamp)
	}
}

// TestRunMigrations_RecordWarnBranch — when the per-filename INSERT into
// schema_migrations fails after the migrations themselves applied, the
// runner must NOT return an error (the migrations succeeded; the
// tracking-row write is best-effort per the doc comment). We force the
// INSERT to fail by pre-creating schema_migrations as a non-updatable
// view masking the real table — every embedded migration still applies
// (CREATE TABLE IF NOT EXISTS sees the view, treats name as taken, no-op)
// but the per-filename INSERT fires against the view and errors with
// "cannot insert into view".
//
// This is the only practical way to exercise the L57-62 warn branch
// without DI; the embedded migrations include 022_schema_migrations
// which would otherwise resurrect the table.
func TestRunMigrations_RecordWarnBranch(t *testing.T) {
	dsn, cleanup := freshTestDB(t)
	defer cleanup()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	// pre-stage: create the table the runner needs (matching the schema
	// from 022_schema_migrations.sql) then swap it out for a view of a
	// different relation that does NOT have a `filename` column. INSERTs
	// against the view fail with "cannot insert into view".
	if _, err := db.Exec(`CREATE TABLE _backing (id INT PRIMARY KEY)`); err != nil {
		t.Fatalf("create _backing: %v", err)
	}
	if _, err := db.Exec(`CREATE VIEW schema_migrations AS SELECT id::text AS filename, now() AS applied_at FROM _backing`); err != nil {
		t.Fatalf("create view: %v", err)
	}

	// Now run the migration set. The "CREATE TABLE IF NOT EXISTS
	// schema_migrations" inside 022 will see a relation with that
	// name and skip. Every other migration applies cleanly. The
	// per-filename INSERT loop then tries to write into the view
	// and emits the warn branch.
	if err := RunMigrations(db); err != nil {
		t.Fatalf("RunMigrations: want nil (warn-only branch), got %v", err)
	}
}

// TestRunMigrations_ExecErrorPropagates injects a closed DB to force the
// Exec branch of RunMigrations to fail. Covers the error-wrapping path
// `db.RunMigrations: exec %s: %w`.
func TestRunMigrations_ExecErrorPropagates(t *testing.T) {
	dsn, cleanup := freshTestDB(t)
	defer cleanup()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	// close it before passing to RunMigrations — every Exec will error
	db.Close()

	err = RunMigrations(db)
	if err == nil {
		t.Fatal("RunMigrations on closed db: want error, got nil")
	}
	if !strings.Contains(err.Error(), "db.RunMigrations") {
		t.Errorf("error wrapping lost: %v", err)
	}
}

// TestErrDBConnect_ErrorAndUnwrap covers both methods on the sentinel.
func TestErrDBConnect_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:1: connection refused")
	e := &ErrDBConnect{Cause: inner}

	if !strings.Contains(e.Error(), "failed to connect to postgres") {
		t.Errorf("Error() prefix: got %q", e.Error())
	}
	if !strings.Contains(e.Error(), "connection refused") {
		t.Errorf("Error() missing cause: %q", e.Error())
	}
	if got := e.Unwrap(); !errors.Is(got, inner) {
		t.Errorf("Unwrap: want inner err, got %v", got)
	}
	// errors.Is should walk through Unwrap correctly
	wrapped := fmt.Errorf("higher: %w", e)
	var target *ErrDBConnect
	if !errors.As(wrapped, &target) {
		t.Error("errors.As did not unwrap ErrDBConnect")
	}
}

// TestErrRedisConnect_ErrorAndUnwrap mirrors the ErrDBConnect test.
func TestErrRedisConnect_ErrorAndUnwrap(t *testing.T) {
	inner := errors.New("EOF")
	e := &ErrRedisConnect{Cause: inner}

	if !strings.Contains(e.Error(), "failed to connect to redis") {
		t.Errorf("Error() prefix: got %q", e.Error())
	}
	if !strings.Contains(e.Error(), "EOF") {
		t.Errorf("Error() missing cause: %q", e.Error())
	}
	if got := e.Unwrap(); !errors.Is(got, inner) {
		t.Errorf("Unwrap: want inner err, got %v", got)
	}
	var target *ErrRedisConnect
	if !errors.As(fmt.Errorf("h: %w", e), &target) {
		t.Error("errors.As did not unwrap ErrRedisConnect")
	}
}

// TestConnectPostgres_Success covers the happy path: real DSN → real
// connection → Stats validates the env-tunable pool knobs were applied.
func TestConnectPostgres_Success(t *testing.T) {
	dsn := testDSN()
	probe, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probe.PingContext(ctx); err != nil {
		probe.Close()
		t.Skipf("postgres ping: %v", err)
	}
	probe.Close()

	// override the pool knobs so we can prove the env path is wired
	t.Setenv("API_PG_MAX_OPEN_CONNS", "7")
	t.Setenv("API_PG_MAX_IDLE_CONNS", "3")
	t.Setenv("API_PG_CONN_MAX_LIFETIME", "2m")
	t.Setenv("API_PG_CONN_MAX_IDLE_TIME", "45s")

	db := ConnectPostgres(dsn)
	defer db.Close()

	if got := db.Stats().MaxOpenConnections; got != 7 {
		t.Errorf("MaxOpenConnections: want 7, got %d", got)
	}
}

// TestConnectPostgres_PanicsOnBadDSN exercises the panic path the way
// startup would: an invalid DSN should panic with *ErrDBConnect.
func TestConnectPostgres_PanicsOnBadDSN(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ConnectPostgres on bad DSN: expected panic")
		}
		e, ok := r.(*ErrDBConnect)
		if !ok {
			t.Errorf("panic value: want *ErrDBConnect, got %T (%v)", r, r)
			return
		}
		if e.Cause == nil {
			t.Error("ErrDBConnect.Cause should be set")
		}
	}()
	// lib/pq sql.Open with an unparseable URL returns an error → panic
	ConnectPostgres("postgres://[::invalid")
}

// TestConnectPostgres_PanicsOnUnreachable — open succeeds (lazy) but
// PingContext fails. Covers the second panic site in ConnectPostgres.
func TestConnectPostgres_PanicsOnUnreachable(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ConnectPostgres on unreachable host: expected panic")
		}
		if _, ok := r.(*ErrDBConnect); !ok {
			t.Errorf("panic value: want *ErrDBConnect, got %T (%v)", r, r)
		}
	}()
	// port 1 on localhost is reserved tcpmux; nothing listens, so ping
	// fails within the 10s timeout in ConnectPostgres.
	ConnectPostgres("postgres://nobody@127.0.0.1:1/postgres?sslmode=disable&connect_timeout=2")
}

// TestConnectRedis_Success — happy path against the local test redis.
func TestConnectRedis_Success(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		url = "redis://localhost:6379/15"
	}
	// best-effort skip on unreachable redis (e.g. CI without the service)
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("redis unreachable, skipping: %v", r)
		}
	}()
	rdb := ConnectRedis(url)
	defer rdb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Errorf("post-connect ping: %v", err)
	}
}

// TestConnectRedis_PanicsOnBadURL covers the ParseURL-failure path.
func TestConnectRedis_PanicsOnBadURL(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ConnectRedis on bad URL: expected panic")
		}
		if _, ok := r.(*ErrRedisConnect); !ok {
			t.Errorf("panic value: want *ErrRedisConnect, got %T", r)
		}
	}()
	ConnectRedis("not-a-redis-url")
}

// TestStartPoolStatsExporter_TickFires covers the ticker.C branch of the
// exporter loop (the eager-emit before the first tick covers the rest).
// The default ticker interval is 5 seconds — we run for 6 to guarantee
// at least one tick fires before context cancellation. Skipped in
// `-short` mode so the default unit-test run stays fast.
func TestStartPoolStatsExporter_TickFires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 6s ticker test in -short mode")
	}
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		StartPoolStatsExporter(ctx, db, "tick_test_pool")
		close(done)
	}()
	select {
	case <-done:
		// good — exited cleanly after at least one tick
	case <-time.After(8 * time.Second):
		t.Fatal("StartPoolStatsExporter did not return")
	}
}

// TestConnectRedis_PanicsOnUnreachable covers the Ping-failure path
// (URL is valid, but no server listens).
func TestConnectRedis_PanicsOnUnreachable(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ConnectRedis on unreachable host: expected panic")
		}
		if _, ok := r.(*ErrRedisConnect); !ok {
			t.Errorf("panic value: want *ErrRedisConnect, got %T", r)
		}
	}()
	// 127.0.0.1:1 has nothing listening; the client retries within 10s
	// then returns the ping error → ConnectRedis panics with *ErrRedisConnect.
	ConnectRedis("redis://127.0.0.1:1/0")
}

// TestMigrations_ResourcesStatusCheck_ForwardConsistent guards the
// 2026-06-10 incident: the migration runner RE-APPLIES every migration on
// each boot. Migration 024 originally re-added a NARROW
// resources_status_check (missing 'suspended' [added 049] and 'pending'
// [added 057]); once a valid row held one of those later-added statuses, the
// 024 re-apply failed with a constraint violation and crashed the api boot
// (prod survived only on a not-yet-restarted pod). Any migration that re-adds
// resources_status_check MUST allow the full canonical status set, so
// re-applying it mid-sequence can never reject a valid row. No DB needed —
// reads the embedded SQL via the same seam the runner uses.
func TestMigrations_ResourcesStatusCheck_ForwardConsistent(t *testing.T) {
	canonical := []string{"pending", "active", "paused", "suspended", "failed", "expired", "deleted", "reaped"}
	checked := 0
	for _, name := range MigrationFiles() {
		b, err := readMigrationFile(name)
		if err != nil {
			t.Fatalf("readMigrationFile(%s): %v", name, err)
		}
		sql := string(b)
		if !strings.Contains(sql, "ADD CONSTRAINT resources_status_check") {
			continue
		}
		checked++
		for _, st := range canonical {
			if !strings.Contains(sql, "'"+st+"'") {
				t.Errorf("%s re-adds resources_status_check but omits status %q — a valid row in that status will crash the api boot when this migration re-applies before a later widening migration. Use the full canonical set: %v", name, st, canonical)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no migration adds resources_status_check — test wiring broken (did the constraint move?)")
	}
}
