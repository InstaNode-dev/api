package models_test

// dbsafety_audit_sink_test.go — covers the *sql.DB-backed dbsafety audit sink
// (truehomie-db hardening). Integration test — needs TEST_DATABASE_URL; skips
// cleanly otherwise.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/models"
	"instant.dev/internal/providers/dbsafety"
	"instant.dev/internal/testhelpers"
)

// TestWireDBSafetyAuditSink_NilIsNoop asserts a nil db leaves the default
// (structured-slog) sink in place rather than installing a panicking nil-db
// sink. Pure — no DB needed.
func TestWireDBSafetyAuditSink_NilIsNoop(t *testing.T) {
	dbsafety.SetAuditSink(nil)
	t.Cleanup(func() { dbsafety.SetAuditSink(nil) })

	models.WireDBSafetyAuditSink(nil) // must NOT install a *sql.DB sink over a nil db

	// A guard against a dev host with valid names triggers exactly one emit;
	// with the default slog sink this must not panic.
	err := dbsafety.GuardDrop(context.Background(), dbsafety.DropParams{
		Provider:     "db.local",
		Env:          dbsafety.EnvDevelopment,
		DSNHost:      "postgres://u:p@localhost:5432/d",
		Token:        "tok",
		DatabaseName: "db_tok",
		UserName:     "usr_tok",
	})
	require.NoError(t, err)
}

// TestDBSafetyAuditSink_EmitWritesRow drives the production sink end-to-end: a
// sanctioned (dev-host, valid-name) GuardDrop emits a customer_db.direct_drop
// audit_log row carrying the destroyed identifiers + DSN host. The emit fires
// from a goroutine, so the row is polled for.
func TestDBSafetyAuditSink_EmitWritesRow(t *testing.T) {
	db, clean := testhelpers.SetupTestDB(t)
	defer clean()

	models.WireDBSafetyAuditSink(db)
	t.Cleanup(func() { dbsafety.SetAuditSink(nil) })

	const token = "auditseam-tok"
	err := dbsafety.GuardDrop(context.Background(), dbsafety.DropParams{
		Provider:     "db.local",
		Env:          dbsafety.EnvDevelopment,
		DSNHost:      "postgres://u:p@postgres-customers:5432/d",
		Token:        token,
		DatabaseName: "db_" + token,
		UserName:     "usr_" + token,
	})
	require.NoError(t, err)

	// Poll for the audit row (team_id is NULL — admin-only rows — so query the
	// kind directly rather than via ListAuditEventsByTeam, which filters team).
	deadline := time.Now().Add(3 * time.Second)
	var (
		gotKind, gotActor, gotSummary, gotMeta string
		found                                  bool
	)
	for {
		row := db.QueryRowContext(context.Background(), `
			SELECT kind, actor, summary, COALESCE(metadata::text, '')
			  FROM audit_log
			 WHERE kind = $1
			   AND metadata->>'token' = $2
			 ORDER BY created_at DESC
			 LIMIT 1
		`, dbsafety.AuditKindCustomerDBDirectDrop, token)
		if err := row.Scan(&gotKind, &gotActor, &gotSummary, &gotMeta); err == nil {
			found = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.True(t, found, "a customer_db.direct_drop audit row must land after a sanctioned drop")

	assert.Equal(t, dbsafety.AuditKindCustomerDBDirectDrop, gotKind)
	assert.Equal(t, "system", gotActor)
	assert.Contains(t, gotSummary, "direct customer-DB drop")

	var meta map[string]string
	require.NoError(t, json.Unmarshal([]byte(gotMeta), &meta))
	assert.Equal(t, "db.local", meta["provider"])
	assert.Equal(t, "db_"+token, meta["database"])
	assert.Equal(t, "usr_"+token, meta["user"])
	assert.Equal(t, "postgres-customers", meta["dsn_host"], "DSN host (no credentials) must be recorded")
}
