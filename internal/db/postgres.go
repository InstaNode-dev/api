package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

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
		content, err := fs.ReadFile(migrationsFS, "migrations/"+name)
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
	entries, err := fs.ReadDir(migrationsFS, "migrations")
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

// ConnectPostgres creates and verifies a *sql.DB connection pool using the lib/pq driver.
// It panics if the connection cannot be established — this is intentional at startup.
func ConnectPostgres(databaseURL string) *sql.DB {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		panic(&ErrDBConnect{Cause: err})
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		panic(&ErrDBConnect{Cause: err})
	}

	slog.Info("db.postgres.connected",
		"max_open_conns", 25,
		"max_idle_conns", 10,
	)
	return db
}
