package testhelpers

// migration_064_test.go — coverage for migration 064
// (forwarder_sent.audit_log_id strict ON DELETE SET NULL FK to audit_log).
//
// Closes CLAUDE.md "Known Design Gaps" #6: a team-deletion cascade drops
// audit_log rows but leaves forwarder_sent rows pointing at non-existent
// audit_log IDs. Migration 063 was index + COMMENT only; 064 adds the
// actual strict FK on a new nullable UUID breadcrumb column.
//
// What this test asserts (registry-walk over pg catalogs, per CLAUDE.md
// rule 18 — no hand-typed lists):
//
//   1. The audit_log_id column exists with type uuid and is nullable.
//   2. The strict FK constraint exists with confdeltype='n' (ON DELETE
//      SET NULL) and targets audit_log.
//   3. The partial index idx_forwarder_sent_audit_log_id_not_null exists.
//   4. End-to-end SET NULL behaviour: inserting a forwarder_sent row that
//      references a real audit_log row, then deleting that audit_log row,
//      causes audit_log_id to flip to NULL — NOT for the row to be
//      deleted (the email-truth-surface ledger row survives) and NOT for
//      the delete to fail with a constraint error.
//   5. Legacy placeholder audit_id strings still insert cleanly with
//      audit_log_id left NULL.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestMigration064_AuditLogIDColumnShape(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	var dataType, isNullable string
	err := db.QueryRow(`
		SELECT data_type, is_nullable
		  FROM information_schema.columns
		 WHERE table_schema = 'public'
		   AND table_name = 'forwarder_sent'
		   AND column_name = 'audit_log_id'
	`).Scan(&dataType, &isNullable)
	require.NoError(t, err, "audit_log_id column must exist on forwarder_sent")
	require.Equal(t, "uuid", dataType, "audit_log_id must be UUID")
	require.Equal(t, "YES", isNullable,
		"audit_log_id must be nullable so placeholder rows + post-cascade rows can hold NULL")
}

func TestMigration064_AuditLogIDFKWithOnDeleteSetNull(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	// pg_constraint walk: confirm the FK exists with the right name,
	// targets audit_log, and has confdeltype='n' (= SET NULL).
	// confdeltype enum: a=NO ACTION, r=RESTRICT, c=CASCADE, n=SET NULL,
	// d=SET DEFAULT.
	var confdeltype, refTable string
	err := db.QueryRow(`
		SELECT c.confdeltype, t.relname
		  FROM pg_constraint c
		  JOIN pg_class t ON t.oid = c.confrelid
		 WHERE c.conname = 'forwarder_sent_audit_log_id_fkey'
		   AND c.contype = 'f'
	`).Scan(&confdeltype, &refTable)
	require.NoError(t, err, "forwarder_sent_audit_log_id_fkey FK must exist")
	require.Equal(t, "n", confdeltype,
		"FK must be ON DELETE SET NULL (confdeltype='n'), got %q", confdeltype)
	require.Equal(t, "audit_log", refTable, "FK must target audit_log table")
}

func TestMigration064_AuditLogIDPartialIndexExists(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	var indexName string
	err := db.QueryRow(`
		SELECT indexname
		  FROM pg_indexes
		 WHERE schemaname = 'public'
		   AND tablename = 'forwarder_sent'
		   AND indexname = 'idx_forwarder_sent_audit_log_id_not_null'
	`).Scan(&indexName)
	require.NoError(t, err,
		"partial index idx_forwarder_sent_audit_log_id_not_null must exist for orphan-reconciler joins")
}

func TestMigration064_OnDeleteSetNullEndToEnd(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	// Set up a real team + audit_log row so the FK has a target.
	teamID := uuid.New()
	_, err := db.Exec(`INSERT INTO teams (id, name) VALUES ($1, $2)`, teamID, "fk-064-team")
	require.NoError(t, err)

	auditID := uuid.New()
	_, err = db.Exec(`
		INSERT INTO audit_log (id, team_id, kind, summary)
		VALUES ($1, $2, 'test.fk064', 'fk-064 audit row')
	`, auditID, teamID)
	require.NoError(t, err)

	// Insert a forwarder_sent row referencing the audit_log row via both
	// the legacy TEXT audit_id (PK + idempotency) and the new strict-FK
	// audit_log_id breadcrumb.
	_, err = db.Exec(`
		INSERT INTO forwarder_sent (audit_id, audit_log_id, provider, classification)
		VALUES ($1, $2, 'brevo', 'success')
	`, auditID.String(), auditID)
	require.NoError(t, err)

	// Delete the audit_log row. ON DELETE SET NULL must flip audit_log_id
	// to NULL on the ledger row WITHOUT deleting the ledger row itself
	// (preserves email-truth-surface semantics — CLAUDE.md rule 12).
	_, err = db.Exec(`DELETE FROM audit_log WHERE id = $1`, auditID)
	require.NoError(t, err)

	var stillExists, auditLogIDIsNull bool
	err = db.QueryRow(`
		SELECT TRUE, audit_log_id IS NULL
		  FROM forwarder_sent
		 WHERE audit_id = $1
	`, auditID.String()).Scan(&stillExists, &auditLogIDIsNull)
	require.NoError(t, err, "ledger row must survive the audit_log delete")
	require.True(t, stillExists, "ledger row must survive")
	require.True(t, auditLogIDIsNull,
		"audit_log_id must be SET NULL by FK after audit_log row deletion")
}

func TestMigration064_LegacyPlaceholderAuditIDStillInsertable(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	// Legacy emit sites write placeholder strings into audit_id that are
	// NOT valid UUIDs. The new audit_log_id column must remain optional
	// so these inserts still succeed (audit_log_id left NULL).
	// Use a per-run nonce so reuse of the test DB across `go test -count=N`
	// runs doesn't trip the PK uniqueness constraint on audit_id.
	nonce := uuid.New().String()
	placeholders := []string{
		"reminder-abc123-stage2-" + nonce,
		"provider-grace-987-" + nonce,
		"audit-row-42-" + nonce,
	}
	for _, p := range placeholders {
		_, err := db.Exec(`
			INSERT INTO forwarder_sent (audit_id, provider, classification)
			VALUES ($1, 'legacy', 'success')
		`, p)
		require.NoErrorf(t, err,
			"placeholder audit_id %q must insert cleanly with audit_log_id NULL", p)
	}
}
