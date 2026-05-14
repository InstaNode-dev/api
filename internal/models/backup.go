package models

// backup.go — CRUD helpers for the resource_backups + resource_restores
// tables introduced in migration 031.
//
// The API only writes 'pending' rows (one per POST /api/v1/resources/:id/backup
// or /restore) and reads rows back for the list endpoints. The worker
// (sibling repo, instanode.dev/worker) owns every state transition —
// pending → running → ok/failed — and stamps finished_at, s3_key,
// size_bytes, error_summary.
//
// Pagination is cursor-style on created_at to avoid offset scans on large
// teams' histories. The handler resolves the cursor by passing a "before"
// timestamp; rows strictly older than that are returned.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BackupKind* are the only legal values for resource_backups.backup_kind.
// Kept as named constants so callers don't drift on capitalisation; the
// CHECK constraint on the column enforces this at the DB layer too.
const (
	BackupKindScheduled = "scheduled"
	BackupKindManual    = "manual"
)

// JobStatus* are the only legal values for resource_backups.status and
// resource_restores.status. Shared between the two tables because the
// worker's state machine is identical: pending → running → terminal.
const (
	JobStatusPending = "pending"
	JobStatusRunning = "running"
	JobStatusOK      = "ok"
	JobStatusFailed  = "failed"
)

// listBackupsMaxLimit caps a single page on GET /backups (and /restores).
// Matches auditMaxLimit's posture — keeps a single call from sweeping a
// large team's history. The dashboard typically requests 50.
const listBackupsMaxLimit = 200

// ResourceBackup is one row in resource_backups.
type ResourceBackup struct {
	ID            uuid.UUID
	ResourceID    uuid.UUID
	Status        string
	BackupKind    string
	StartedAt     time.Time
	FinishedAt    sql.NullTime
	S3Key         sql.NullString
	SizeBytes     sql.NullInt64
	TierAtBackup  sql.NullString
	ErrorSummary  sql.NullString
	TriggeredBy   uuid.NullUUID
	CreatedAt     time.Time
}

// ResourceRestore is one row in resource_restores. Mirrors ResourceBackup
// minus the size/s3 fields (restores don't produce artifacts) plus a
// non-null BackupID + TriggeredBy.
type ResourceRestore struct {
	ID           uuid.UUID
	ResourceID   uuid.UUID
	BackupID     uuid.UUID
	Status       string
	StartedAt    time.Time
	FinishedAt   sql.NullTime
	ErrorSummary sql.NullString
	TriggeredBy  uuid.UUID
	CreatedAt    time.Time
}

// CreateBackupParams is the input for CreateBackupRow. The handler builds it
// from the request — no defaulting happens at the model layer except for
// status (always 'pending' on insert).
type CreateBackupParams struct {
	ResourceID   uuid.UUID
	BackupKind   string         // BackupKindScheduled | BackupKindManual
	TierAtBackup string         // snapshot of team.plan_tier at request time
	TriggeredBy  uuid.NullUUID  // NULL for scheduled (no human), non-null for manual
}

// CreateBackupRow inserts a pending resource_backups row and returns it.
// status is hard-coded 'pending'; the worker is the only writer of any
// other status. Returns the full row so the handler can echo the id and
// started_at back to the caller.
func CreateBackupRow(ctx context.Context, db *sql.DB, p CreateBackupParams) (*ResourceBackup, error) {
	row := db.QueryRowContext(ctx, `
		INSERT INTO resource_backups
			(resource_id, status, backup_kind, tier_at_backup, triggered_by)
		VALUES ($1, 'pending', $2, NULLIF($3,''), $4)
		RETURNING id, resource_id, status, backup_kind, started_at, finished_at,
		          s3_key, size_bytes, tier_at_backup, error_summary, triggered_by, created_at
	`, p.ResourceID, p.BackupKind, p.TierAtBackup, p.TriggeredBy)

	b := &ResourceBackup{}
	if err := row.Scan(
		&b.ID, &b.ResourceID, &b.Status, &b.BackupKind, &b.StartedAt, &b.FinishedAt,
		&b.S3Key, &b.SizeBytes, &b.TierAtBackup, &b.ErrorSummary, &b.TriggeredBy, &b.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("models.CreateBackupRow: %w", err)
	}
	return b, nil
}

// GetBackupByID fetches a single backup row by its id. Returns sql.ErrNoRows
// when the row does not exist (caller maps to 404). The caller is responsible
// for ownership checks — this function does NO authz.
func GetBackupByID(ctx context.Context, db *sql.DB, id uuid.UUID) (*ResourceBackup, error) {
	row := db.QueryRowContext(ctx, `
		SELECT id, resource_id, status, backup_kind, started_at, finished_at,
		       s3_key, size_bytes, tier_at_backup, error_summary, triggered_by, created_at
		FROM resource_backups
		WHERE id = $1
	`, id)
	b := &ResourceBackup{}
	if err := row.Scan(
		&b.ID, &b.ResourceID, &b.Status, &b.BackupKind, &b.StartedAt, &b.FinishedAt,
		&b.S3Key, &b.SizeBytes, &b.TierAtBackup, &b.ErrorSummary, &b.TriggeredBy, &b.CreatedAt,
	); err != nil {
		return nil, err // includes sql.ErrNoRows for the handler to detect
	}
	return b, nil
}

// ListBackupsByResource returns backups for a resource ordered newest-first.
// Cursor-style pagination: when `before` is non-zero, only rows with
// created_at < before are returned. Limit is capped at listBackupsMaxLimit.
//
// The list is NOT filtered by status — the worker's terminal failures
// (status='failed', error_summary set) are returned so the dashboard can
// show "backup failed at 03:00 UTC, contact support" without a separate
// audit-log fetch.
func ListBackupsByResource(ctx context.Context, db *sql.DB, resourceID uuid.UUID, limit int, before time.Time) ([]*ResourceBackup, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > listBackupsMaxLimit {
		limit = listBackupsMaxLimit
	}

	var rows *sql.Rows
	var err error
	if before.IsZero() {
		rows, err = db.QueryContext(ctx, `
			SELECT id, resource_id, status, backup_kind, started_at, finished_at,
			       s3_key, size_bytes, tier_at_backup, error_summary, triggered_by, created_at
			FROM resource_backups
			WHERE resource_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, resourceID, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, resource_id, status, backup_kind, started_at, finished_at,
			       s3_key, size_bytes, tier_at_backup, error_summary, triggered_by, created_at
			FROM resource_backups
			WHERE resource_id = $1 AND created_at < $2
			ORDER BY created_at DESC
			LIMIT $3
		`, resourceID, before, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("models.ListBackupsByResource: %w", err)
	}
	defer rows.Close()

	out := make([]*ResourceBackup, 0)
	for rows.Next() {
		b := &ResourceBackup{}
		if err := rows.Scan(
			&b.ID, &b.ResourceID, &b.Status, &b.BackupKind, &b.StartedAt, &b.FinishedAt,
			&b.S3Key, &b.SizeBytes, &b.TierAtBackup, &b.ErrorSummary, &b.TriggeredBy, &b.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListBackupsByResource scan: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListBackupsByResource rows: %w", err)
	}
	return out, nil
}

// CountBackupsByResource returns the total number of backup rows for a resource,
// used by the list endpoint to populate `total` alongside the (paged) items.
// Counts every row regardless of status — same shape as the list query.
func CountBackupsByResource(ctx context.Context, db *sql.DB, resourceID uuid.UUID) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resource_backups WHERE resource_id = $1`,
		resourceID,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("models.CountBackupsByResource: %w", err)
	}
	return n, nil
}

// CreateRestoreParams is the input for CreateRestoreRow. backup_id MUST
// reference an existing resource_backups row in status='ok' — the handler
// verifies this before calling.
type CreateRestoreParams struct {
	ResourceID  uuid.UUID
	BackupID    uuid.UUID
	TriggeredBy uuid.UUID
}

// CreateRestoreRow inserts a pending resource_restores row and returns it.
// status is hard-coded 'pending'; the worker is the only writer of any
// other status.
func CreateRestoreRow(ctx context.Context, db *sql.DB, p CreateRestoreParams) (*ResourceRestore, error) {
	row := db.QueryRowContext(ctx, `
		INSERT INTO resource_restores (resource_id, backup_id, status, triggered_by)
		VALUES ($1, $2, 'pending', $3)
		RETURNING id, resource_id, backup_id, status, started_at, finished_at,
		          error_summary, triggered_by, created_at
	`, p.ResourceID, p.BackupID, p.TriggeredBy)

	r := &ResourceRestore{}
	if err := row.Scan(
		&r.ID, &r.ResourceID, &r.BackupID, &r.Status, &r.StartedAt, &r.FinishedAt,
		&r.ErrorSummary, &r.TriggeredBy, &r.CreatedAt,
	); err != nil {
		return nil, fmt.Errorf("models.CreateRestoreRow: %w", err)
	}
	return r, nil
}

// ListRestoresByResource — same shape and semantics as ListBackupsByResource.
func ListRestoresByResource(ctx context.Context, db *sql.DB, resourceID uuid.UUID, limit int, before time.Time) ([]*ResourceRestore, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > listBackupsMaxLimit {
		limit = listBackupsMaxLimit
	}

	var rows *sql.Rows
	var err error
	if before.IsZero() {
		rows, err = db.QueryContext(ctx, `
			SELECT id, resource_id, backup_id, status, started_at, finished_at,
			       error_summary, triggered_by, created_at
			FROM resource_restores
			WHERE resource_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		`, resourceID, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, resource_id, backup_id, status, started_at, finished_at,
			       error_summary, triggered_by, created_at
			FROM resource_restores
			WHERE resource_id = $1 AND created_at < $2
			ORDER BY created_at DESC
			LIMIT $3
		`, resourceID, before, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("models.ListRestoresByResource: %w", err)
	}
	defer rows.Close()

	out := make([]*ResourceRestore, 0)
	for rows.Next() {
		r := &ResourceRestore{}
		if err := rows.Scan(
			&r.ID, &r.ResourceID, &r.BackupID, &r.Status, &r.StartedAt, &r.FinishedAt,
			&r.ErrorSummary, &r.TriggeredBy, &r.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("models.ListRestoresByResource scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("models.ListRestoresByResource rows: %w", err)
	}
	return out, nil
}

// CountRestoresByResource — mirror of CountBackupsByResource.
func CountRestoresByResource(ctx context.Context, db *sql.DB, resourceID uuid.UUID) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM resource_restores WHERE resource_id = $1`,
		resourceID,
	).Scan(&n); err != nil {
		return 0, fmt.Errorf("models.CountRestoresByResource: %w", err)
	}
	return n, nil
}
