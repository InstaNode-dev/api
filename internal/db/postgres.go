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
func RunMigrations(db *sql.DB) error {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("db.RunMigrations: read dir: %w", err)
	}

	// Collect only .sql files and sort alphabetically.
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

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
	return nil
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
