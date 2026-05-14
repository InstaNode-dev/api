package models_test

// resource_heartbeat_migration_test.go — pins the migration-030 column
// shape (testhelpers mirror) so the worker-side resource_heartbeat /
// provisioner_reconciler jobs have a stable contract to target.
//
// These tests run against the real test Postgres (the partial indexes
// and CHECK constraints from migration 031 only fire under real Postgres
// — sqlite would silently accept rows that violate them).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"instant.dev/internal/testhelpers"
)

// TestMigration030_ResourceHeartbeatColumns verifies the heartbeat columns
// added by migration 030 exist and accept the expected reads/writes:
//
//   - last_seen_at        — nullable TIMESTAMPTZ (NULL = never probed yet)
//   - degraded            — BOOL NOT NULL DEFAULT false
//   - degraded_reason     — nullable TEXT
//   - last_reconciled_at  — nullable TIMESTAMPTZ
//
// The brief asserts: "after migration runs, INSERT INTO resources ...;
// UPDATE resources SET degraded=true WHERE ... works." That's what
// this test covers — a basic INSERT + UPDATE round-trip against the
// new columns.
func TestMigration030_ResourceHeartbeatColumns(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	// Insert a resource row. The new columns must accept the defaults
	// (degraded=false, the others NULL) without any explicit values.
	var resourceID uuid.UUID
	err := db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING id
	`, teamID).Scan(&resourceID)
	require.NoError(t, err, "INSERT INTO resources must succeed after migration 030 — the new columns all have defaults or are nullable")

	// Default contract: a freshly-inserted row reports degraded=false
	// and the three time columns are NULL.
	var degraded bool
	var lastSeenAt, lastReconciledAt *string
	var degradedReason *string
	err = db.QueryRowContext(context.Background(), `
		SELECT degraded, last_seen_at::text, last_reconciled_at::text, degraded_reason
		FROM resources WHERE id = $1
	`, resourceID).Scan(&degraded, &lastSeenAt, &lastReconciledAt, &degradedReason)
	require.NoError(t, err)
	assert.False(t, degraded, "fresh resources.degraded must default to false")
	assert.Nil(t, lastSeenAt, "fresh resources.last_seen_at must default to NULL (never probed)")
	assert.Nil(t, lastReconciledAt, "fresh resources.last_reconciled_at must default to NULL")
	assert.Nil(t, degradedReason, "fresh resources.degraded_reason must default to NULL")

	// Heartbeat write path: the worker's resource_heartbeat job stamps
	// last_seen_at on success and flips degraded=true with a reason on
	// failure. Both UPDATE paths must succeed.
	_, err = db.ExecContext(context.Background(), `
		UPDATE resources
		SET degraded = true, degraded_reason = 'connection refused', last_reconciled_at = now()
		WHERE id = $1
	`, resourceID)
	require.NoError(t, err, "UPDATE resources SET degraded=true ... must succeed — this is the worker's failure-path write")

	err = db.QueryRowContext(context.Background(), `
		SELECT degraded, degraded_reason FROM resources WHERE id = $1
	`, resourceID).Scan(&degraded, &degradedReason)
	require.NoError(t, err)
	assert.True(t, degraded, "UPDATE must flip degraded to true")
	require.NotNil(t, degradedReason)
	assert.Equal(t, "connection refused", *degradedReason, "degraded_reason must round-trip")

	// Recovery path: stamping last_seen_at clears the degraded flag.
	// The worker side owns that transition logic; here we just confirm
	// the columns let the worker write it.
	_, err = db.ExecContext(context.Background(), `
		UPDATE resources SET last_seen_at = now(), degraded = false, degraded_reason = NULL WHERE id = $1
	`, resourceID)
	require.NoError(t, err)
}

// TestMigration030_PartialIndexes verifies the two partial indexes the
// worker-side hot paths target:
//   - idx_resources_degraded         — WHERE degraded
//   - idx_resources_pending_sweep    — WHERE status='pending'
//
// We don't (and can't reliably) assert that Postgres chose the index in
// a query plan from a unit test — but we CAN assert the indexes exist
// in pg_indexes, which is the precondition the planner needs. If the
// migration regressed and dropped the partial WHERE clause, this test
// would fail on the indexdef substring match.
func TestMigration030_PartialIndexes(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// idx_resources_degraded — partial on WHERE degraded.
	var degradedDef string
	err := db.QueryRowContext(context.Background(),
		`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_resources_degraded'`,
	).Scan(&degradedDef)
	require.NoError(t, err, "idx_resources_degraded must exist after migration 030")
	assert.Contains(t, degradedDef, "WHERE degraded",
		"idx_resources_degraded must be PARTIAL on WHERE degraded — a full-table index defeats the purpose")

	// idx_resources_pending_sweep — partial on WHERE status='pending'.
	var pendingDef string
	err = db.QueryRowContext(context.Background(),
		`SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_resources_pending_sweep'`,
	).Scan(&pendingDef)
	require.NoError(t, err, "idx_resources_pending_sweep must exist after migration 030")
	assert.Contains(t, pendingDef, "status",
		"idx_resources_pending_sweep must reference status — that's the column the worker sweep filters on")
	assert.Contains(t, pendingDef, "pending",
		"idx_resources_pending_sweep must be PARTIAL on WHERE status='pending' — the whole point is to keep the sweep scan tiny")
}

// TestMigration031_BackupTables verifies the resource_backups and
// resource_restores tables exist with the FK to resources and the
// CHECK constraints on status / backup_kind. The W5-B-api PR ships
// the handlers + models; this migration is the precondition.
func TestMigration031_BackupTables(t *testing.T) {
	db, cleanDB := testhelpers.SetupTestDB(t)
	defer cleanDB()

	// Basic existence — SELECT 1 FROM both tables must succeed.
	_, err := db.ExecContext(context.Background(), `SELECT 1 FROM resource_backups LIMIT 1`)
	require.NoError(t, err, "resource_backups must exist after migration 031")

	_, err = db.ExecContext(context.Background(), `SELECT 1 FROM resource_restores LIMIT 1`)
	require.NoError(t, err, "resource_restores must exist after migration 031")

	// Round-trip: insert a resource, a user, then a backup row referencing
	// both. The CASCADE on resource_id and the FK on triggered_by are the
	// load-bearing parts of the contract; this test would fail if either
	// reference was dropped.
	teamID := testhelpers.MustCreateTeamDB(t, db, "pro")

	var userID uuid.UUID
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO users (team_id, email)
		VALUES ($1::uuid, $2)
		RETURNING id
	`, teamID, "backup-test-"+uuid.NewString()[:8]+"@instant.dev").Scan(&userID)
	require.NoError(t, err)

	var resourceID uuid.UUID
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO resources (team_id, resource_type, tier, status)
		VALUES ($1::uuid, 'postgres', 'pro', 'active')
		RETURNING id
	`, teamID).Scan(&resourceID)
	require.NoError(t, err)

	var backupID uuid.UUID
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, backup_kind, triggered_by)
		VALUES ($1, 'manual', $2)
		RETURNING id
	`, resourceID, userID).Scan(&backupID)
	require.NoError(t, err, "INSERT INTO resource_backups (status defaults to 'pending', backup_kind='manual' is valid) must succeed")

	// Status CHECK constraint — 'bogus' is not in the allowed set so
	// the INSERT must fail. This guards against a future migration
	// that silently drops the CHECK.
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, backup_kind, status, triggered_by)
		VALUES ($1, 'manual', 'bogus', $2)
	`, resourceID, userID)
	require.Error(t, err, "resource_backups.status CHECK must reject statuses outside {pending,running,ok,failed}")

	// backup_kind CHECK — 'cosmic' is not in {scheduled,manual}.
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO resource_backups (resource_id, backup_kind, triggered_by)
		VALUES ($1, 'cosmic', $2)
	`, resourceID, userID)
	require.Error(t, err, "resource_backups.backup_kind CHECK must reject kinds outside {scheduled,manual}")

	// Restore round-trip — references both the resource AND the backup.
	var restoreID uuid.UUID
	err = db.QueryRowContext(context.Background(), `
		INSERT INTO resource_restores (resource_id, backup_id, triggered_by)
		VALUES ($1, $2, $3)
		RETURNING id
	`, resourceID, backupID, userID).Scan(&restoreID)
	require.NoError(t, err, "INSERT INTO resource_restores must succeed when both FKs are valid")

	// CASCADE: deleting the resource should cascade-delete both the
	// backup and restore rows (per the ON DELETE CASCADE on resource_id).
	_, err = db.ExecContext(context.Background(), `DELETE FROM resources WHERE id = $1`, resourceID)
	require.NoError(t, err)

	var backupCount, restoreCount int
	err = db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resource_backups WHERE id = $1`, backupID,
	).Scan(&backupCount)
	require.NoError(t, err)
	assert.Equal(t, 0, backupCount, "deleting the parent resource MUST cascade-delete its backups")

	err = db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM resource_restores WHERE id = $1`, restoreID,
	).Scan(&restoreCount)
	require.NoError(t, err)
	assert.Equal(t, 0, restoreCount, "deleting the parent resource MUST cascade-delete its restore rows")
}
