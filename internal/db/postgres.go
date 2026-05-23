package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Seams for testing genuinely-unreachable error branches. Production code
// always uses the real embedded FS + lib/pq driver; tests swap these to
// drive the embed-read / driver-open failure paths that can't otherwise
// be reached because the FS is compiled in and lib/pq opens lazily.
var (
	readMigrationDir  = func() ([]fs.DirEntry, error) { return fs.ReadDir(migrationsFS, "migrations") }
	readMigrationFile = func(name string) ([]byte, error) { return fs.ReadFile(migrationsFS, "migrations/"+name) }
	sqlOpen           = sql.Open
)

// RunMigrations executes all embedded SQL migration files in alphabetical order.
// All SQL files use CREATE TABLE IF NOT EXISTS / ALTER TABLE ADD COLUMN IF NOT EXISTS /
// CREATE INDEX IF NOT EXISTS — safe to re-run on every startup.
//
// After all files run, each filename is recorded in schema_migrations
// (created by 022_schema_migrations.sql) with ON CONFLICT DO NOTHING so
// GET /healthz can surface migration_version + migration_count. The
// INSERT is best-effort: a failure to record (e.g. on a fresh DB before
// 022 has run for the first time on this exact connection) is logged
// but does not fail the startup gate.
func RunMigrations(db *sql.DB) error {
	names, err := embeddedMigrationFilenames()
	if err != nil {
		return fmt.Errorf("db.RunMigrations: %w", err)
	}

	for _, name := range names {
		content, err := readMigrationFile(name)
		if err != nil {
			return fmt.Errorf("db.RunMigrations: read %s: %w", name, err)
		}
		slog.Info("db.migrations.applying", "file", name)
		if _, err := db.Exec(string(content)); err != nil {
			return fmt.Errorf("db.RunMigrations: exec %s: %w", name, err)
		}
	}

	// Record every successfully-applied filename. ON CONFLICT preserves
	// the original applied_at for migrations seen on a previous boot.
	// The schema_migrations table itself is created by one of the
	// migrations above, so this loop runs after the table exists.
	for _, name := range names {
		if _, err := db.Exec(
			`INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT (filename) DO NOTHING`,
			name,
		); err != nil {
			// Don't fail startup on a tracking-row insert. The migration
			// itself applied successfully (we just exec'd it above); the
			// /healthz tracking surface is best-effort.
			slog.Warn("db.migrations.record_failed", "file", name, "error", err)
		}
	}
	return nil
}

// embeddedMigrationFilenames returns the sorted list of embedded migration
// filenames. Exported via MigrationFiles for read-only callers that want
// to compare the in-binary set against the DB-tracked set.
func embeddedMigrationFilenames() ([]string, error) {
	entries, err := readMigrationDir()
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// MigrationFiles returns the sorted list of .sql filenames compiled into
// this binary's embedded migration set. Read-only. Used by tests and by
// internal/migrations to sanity-check that the DB-reported filename
// actually exists in the binary.
func MigrationFiles() []string {
	names, _ := embeddedMigrationFilenames()
	return names
}

// ErrDBConnect is returned when the Postgres connection cannot be established.
type ErrDBConnect struct {
	Cause error
}

func (e *ErrDBConnect) Error() string {
	return fmt.Sprintf("failed to connect to postgres: %v", e.Cause)
}

func (e *ErrDBConnect) Unwrap() error { return e.Cause }

// Pool-size defaults used when the corresponding env var is unset or invalid.
//
// Wave-3 chaos verify (2026-05-21) found that a 50-concurrent /db/new burst
// against the DO Managed Postgres host exhausted the connection slots and
// took down event_email_forwarder with "remaining connection slots are
// reserved for non-replication superuser connections". The api pool was
// pinned at 25/10 with handlers holding connections through the full
// provisioner gRPC round-trip (~5-30s sync). Two pools (api + worker) at
// 25 each = 50 slots against DO Managed Postgres' default ~22 user slots
// after the reserved-superuser carveout.
//
// New defaults:
//   - MaxOpen 15 — leaves headroom under the DO Managed ceiling for worker
//     + ad-hoc sessions; can be raised via env when the operator bumps the
//     DO Managed pool tier.
//   - MaxIdle 5 — modest idle pool to absorb burst without holding a
//     pool's worth of conns idle on the upstream.
//   - ConnMaxLifetime 4m — rotates connections so DO Managed routing /
//     failover doesn't strand a stale conn forever.
//   - ConnMaxIdleTime 90s — drops idle conns faster than ConnMaxLifetime
//     so an idle process doesn't hold the pool's worth of slots.
//
// Tunable via env so the operator can raise the ceiling without a redeploy
// the moment the DO Managed Postgres tier is bumped. All env vars are read
// at startup only — there is no hot-reload.
const (
	defaultPGMaxOpenConns  = 15
	defaultPGMaxIdleConns  = 5
	defaultPGConnMaxLife   = 4 * time.Minute
	defaultPGConnMaxIdle   = 90 * time.Second
)

// envInt reads a positive integer from an env var, falling back to def.
// Bad values fall back too — api must not refuse to start on a typo.
func envInt(name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// envDuration reads a duration from an env var (e.g. "5m", "90s"),
// falling back to def. Bad values fall back too.
func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// ConnectPostgres creates and verifies a *sql.DB connection pool using the lib/pq driver.
// It panics if the connection cannot be established — this is intentional at startup.
//
// Pool sizing is tunable via env so the operator can raise the ceiling
// without a redeploy the moment the DO Managed Postgres tier is bumped:
//
//	API_PG_MAX_OPEN_CONNS   (default 15) — per-replica hard ceiling
//	API_PG_MAX_IDLE_CONNS   (default 5)
//	API_PG_CONN_MAX_LIFETIME (default 4m) — Go time.Duration
//	API_PG_CONN_MAX_IDLE_TIME (default 90s)
func ConnectPostgres(databaseURL string) *sql.DB {
	db, err := sqlOpen("postgres", databaseURL)
	if err != nil {
		panic(&ErrDBConnect{Cause: err})
	}

	maxOpen := envInt("API_PG_MAX_OPEN_CONNS", defaultPGMaxOpenConns)
	maxIdle := envInt("API_PG_MAX_IDLE_CONNS", defaultPGMaxIdleConns)
	connLife := envDuration("API_PG_CONN_MAX_LIFETIME", defaultPGConnMaxLife)
	connIdle := envDuration("API_PG_CONN_MAX_IDLE_TIME", defaultPGConnMaxIdle)

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connLife)
	db.SetConnMaxIdleTime(connIdle)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		panic(&ErrDBConnect{Cause: err})
	}

	slog.Info("db.postgres.connected",
		"max_open_conns", maxOpen,
		"max_idle_conns", maxIdle,
		"conn_max_lifetime", connLife.String(),
		"conn_max_idle_time", connIdle.String(),
	)
	return db
}
