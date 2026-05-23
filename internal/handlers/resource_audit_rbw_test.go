package handlers

// Direct coverage for the three best-effort audit emitters in resource.go.
// They are unexported and run as detached goroutines from the handlers, so
// they're exercised here directly. Cannot import testhelpers (it imports this
// package → cycle), so the DB is opened raw against TEST_DATABASE_URL; the
// schema is already migrated by the package's external testhelpers-driven
// tests sharing the same instant_dev_test database.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func openAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("open: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("ping: %v", err)
	}
	return db
}

func mustTeamRow(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	var id string
	if err := db.QueryRowContext(context.Background(),
		`INSERT INTO teams (name, plan_tier) VALUES ($1,'pro') RETURNING id::text`,
		"rbw-audit-"+uuid.NewString()[:8],
	).Scan(&id); err != nil {
		t.Skipf("insert team (schema not migrated?): %v", err)
	}
	return uuid.MustParse(id)
}

func TestEmitAuditFns_Success_RBW(t *testing.T) {
	db := openAuditTestDB(t)
	defer db.Close()
	teamID := mustTeamRow(t, db)
	userID := uuid.NewString() // valid UUID → user-actor arm
	resID := uuid.New()

	emitResourceReadAudit(db, teamID, userID, resID, "postgres")
	emitResourceListByTeamAudit(db, teamID, userID, 3, "production")
	emitConnectionURLDecryptedAudit(db, teamID, userID, resID, "customer_reveal")

	// Non-UUID userID → parse guard false branch (actor stays system).
	emitResourceReadAudit(db, teamID, "not-a-uuid", resID, "redis")
	emitResourceListByTeamAudit(db, teamID, "not-a-uuid", 0, "")
	emitConnectionURLDecryptedAudit(db, teamID, "not-a-uuid", resID, "credential_rotation")
}

func TestEmitAuditFns_InsertError_RBW(t *testing.T) {
	db := openAuditTestDB(t)
	teamID := mustTeamRow(t, db)
	db.Close() // close pool → InsertAuditEvent errors → warn arm

	userID := uuid.NewString()
	resID := uuid.New()
	emitResourceReadAudit(db, teamID, userID, resID, "postgres")
	emitResourceListByTeamAudit(db, teamID, userID, 1, "production")
	emitConnectionURLDecryptedAudit(db, teamID, userID, resID, "customer_reveal")
}
