package models

// team_deletion.go — GDPR Article 17 right-to-be-forgotten state-machine
// helpers backing DELETE /api/v1/team, POST /api/v1/team/restore, and the
// worker's team_deletion_executor sweep.
//
// The state machine has four statuses on teams.status:
//
//	active              — normal team, the default for every row.
//	deletion_requested  — owner has asked for deletion; 30-day grace clock
//	                      runs from deletion_requested_at. Resources are
//	                      paused. The Razorpay subscription is cancelled
//	                      BEFORE the row is flipped (DELETE /api/v1/team
//	                      aborts if the cancel fails — see team_deletion.go
//	                      handler) so a pending-deletion team can never
//	                      keep getting charged. Restorable.
//	deletion_pending    — the worker's executor has BEGUN post-grace
//	                      destruction (drop customer DBs / k8s namespaces /
//	                      S3 backups). The row sits here for the duration of
//	                      the teardown. A mid-pipeline failure leaves the row
//	                      HERE — not half-tombstoned — so the orphan-sweep
//	                      reconciler can resume and finish. NOT restorable:
//	                      destruction has started.
//	tombstoned          — worker has destroyed customer DBs / k8s / S3
//	                      backups / PII fields. NOT restorable. Row stub
//	                      retained for foreign-key integrity on historical
//	                      audit_log entries.
//
// Lifecycle:
//
//	active → deletion_requested → deletion_pending → tombstoned
//	               │                     │
//	               └─(restore)           └─(reconciler retries on failure)
//
// All transitions live here so the producers (handler + worker) and the
// readers (dashboard) hit the same atomic predicates.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// TeamStatusActive / Pending / Tombstoned are the named constants for the
// teams.status enum. Kept as Go consts rather than scattered string literals
// so the handler, the worker, and the dashboard all match exactly.
const (
	TeamStatusActive            = "active"
	TeamStatusDeletionRequested = "deletion_requested"
	// TeamStatusDeletionPending marks a team whose post-grace destruction
	// is in flight. The worker's executor flips deletion_requested →
	// deletion_pending the instant it begins teardown; a crash mid-teardown
	// leaves the row here, and the orphan-sweep reconciler resumes it.
	TeamStatusDeletionPending = "deletion_pending"
	TeamStatusTombstoned      = "tombstoned"

	// TeamDeletionGraceDays is the right-to-be-forgotten grace window. 30
	// days matches the GDPR Article 17 "without undue delay" guidance and
	// gives a customer who clicked delete by mistake a generous undo
	// window. The worker's nightly executor sweeps any row older than
	// this; the restore endpoint rejects any request past it.
	TeamDeletionGraceDays = 30
)

// ErrTeamNotPendingDeletion is returned by RestoreTeam when the row exists
// but is not in deletion_requested status (already active, already
// tombstoned). The handler maps this to 409 Conflict — the action is
// idempotent-friendly but the precondition wasn't met.
var ErrTeamNotPendingDeletion = errors.New("models: team is not in deletion_requested status")

// ErrTeamRestoreGraceExpired is returned by RestoreTeam when the row is
// pending deletion but the 30-day grace window has elapsed. The handler
// maps this to 410 Gone — the deletion has effectively committed even
// though the worker hasn't tombstoned the row yet.
var ErrTeamRestoreGraceExpired = errors.New("models: team restore grace window has expired")

// RequestTeamDeletion atomically flips teams.status from 'active' to
// 'deletion_requested' and stamps deletion_requested_at.
//
// The WHERE status='active' guard makes the operation idempotency-safe:
// a redelivered DELETE call (browser refresh, retry storm) hits the
// guard and gets a zero-rows-affected, which the handler can surface as
// 409 already-pending rather than silently double-stamping the timestamp.
//
// Caller is expected to have already verified caller-is-owner and the
// confirm-slug match. This function does no authz.
func RequestTeamDeletion(ctx context.Context, db *sql.DB, teamID uuid.UUID) error {
	res, err := db.ExecContext(ctx, `
		UPDATE teams
		   SET status = 'deletion_requested',
		       deletion_requested_at = now()
		 WHERE id = $1 AND status = 'active'
	`, teamID)
	if err != nil {
		return fmt.Errorf("models.RequestTeamDeletion: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrTeamNotPendingDeletion
	}
	return nil
}

// RestoreTeam atomically flips teams.status from 'deletion_requested'
// back to 'active' IF the 30-day grace window has not yet elapsed.
//
// Two-stage guard:
//  1. SQL WHERE clause enforces "still deletion_requested AND
//     deletion_requested_at + grace > now()" so we never resurrect a
//     row whose worker-side destruction has already started.
//  2. Zero-rows-affected is disambiguated via a follow-up SELECT — we
//     need to know whether the failure was "not pending" vs
//     "grace expired" so the handler returns the right status code.
func RestoreTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID) error {
	res, err := db.ExecContext(ctx, fmt.Sprintf(`
		UPDATE teams
		   SET status = 'active',
		       deletion_requested_at = NULL
		 WHERE id = $1
		   AND status = 'deletion_requested'
		   AND deletion_requested_at + interval '%d days' > now()
	`, TeamDeletionGraceDays), teamID)
	if err != nil {
		return fmt.Errorf("models.RestoreTeam: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 1 {
		return nil
	}
	// Disambiguate failure mode for the handler.
	var status string
	var requestedAt sql.NullTime
	err = db.QueryRowContext(ctx, `
		SELECT status, deletion_requested_at FROM teams WHERE id = $1
	`, teamID).Scan(&status, &requestedAt)
	if err == sql.ErrNoRows {
		return &ErrTeamNotFound{ID: teamID}
	}
	if err != nil {
		return fmt.Errorf("models.RestoreTeam disambiguate: %w", err)
	}
	if status != TeamStatusDeletionRequested {
		return ErrTeamNotPendingDeletion
	}
	// Status matches but the UPDATE missed — the grace window must be
	// expired (or the timestamp is NULL, which we treat as expired since
	// a pending-deletion row with no timestamp is corrupt and should not
	// be restorable).
	return ErrTeamRestoreGraceExpired
}

// MarkTeamDeletionPending atomically flips teams.status from
// 'deletion_requested' to 'deletion_pending'. The worker's executor calls
// this the instant it begins post-grace destruction, so:
//
//   - a mid-teardown crash leaves the row in deletion_pending (visibly
//     "destruction in flight, did not finish") rather than indistinguishable
//     from a team still inside its grace window;
//   - the restore endpoint, which only matches status='deletion_requested',
//     automatically refuses once destruction has started;
//   - the operation is idempotent: a re-run of the executor over a row
//     already flipped to deletion_pending gets 0 rows affected and
//     returns ErrTeamNotPendingDeletion, which the caller treats as
//     "already in the destruction phase, proceed".
//
// deletionRequestedAt is the timestamp the candidate scan already read; we
// keep it in the WHERE clause so a row whose grace window was somehow reset
// (an out-of-band UPDATE) is not swept by a stale candidate list.
func MarkTeamDeletionPending(ctx context.Context, db *sql.DB, teamID uuid.UUID) (bool, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE teams
		   SET status = 'deletion_pending'
		 WHERE id = $1 AND status = 'deletion_requested'
	`, teamID)
	if err != nil {
		return false, fmt.Errorf("models.MarkTeamDeletionPending: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// TeamDeletionStatus is the snapshot the dashboard and the handler's 200
// body need: where the team is in the deletion lifecycle and how long
// until the worker tombstones it.
type TeamDeletionStatus struct {
	Status              string
	DeletionRequestedAt sql.NullTime
	TombstonedAt        sql.NullTime
}

// DeletionAt returns the wall-clock instant the worker will tombstone
// this team, or zero-time if the team is not pending deletion. Computed
// as deletion_requested_at + 30 days; callers serialise this as the
// deletion_at field on the 202 response.
func (s TeamDeletionStatus) DeletionAt() time.Time {
	if !s.DeletionRequestedAt.Valid {
		return time.Time{}
	}
	return s.DeletionRequestedAt.Time.Add(time.Duration(TeamDeletionGraceDays) * 24 * time.Hour)
}

// GetTeamDeletionStatus returns the lifecycle snapshot for a team. Used
// by the handler's response builders and by the worker's sweep to decide
// which step to run next.
func GetTeamDeletionStatus(ctx context.Context, db *sql.DB, teamID uuid.UUID) (*TeamDeletionStatus, error) {
	s := &TeamDeletionStatus{}
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(status, 'active'), deletion_requested_at, tombstoned_at
		  FROM teams WHERE id = $1
	`, teamID).Scan(&s.Status, &s.DeletionRequestedAt, &s.TombstonedAt)
	if err == sql.ErrNoRows {
		return nil, &ErrTeamNotFound{ID: teamID}
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetTeamDeletionStatus: %w", err)
	}
	return s, nil
}

// ResumeAllTeamResources flips every paused team-owned resource back to
// 'active' and clears paused_at. Mirror of PauseAllTeamResources, used
// by the restore endpoint. The connection_url is preserved unchanged —
// the customer's credentials still work after restore.
func ResumeAllTeamResources(ctx context.Context, db *sql.DB, teamID uuid.UUID) (int64, error) {
	res, err := db.ExecContext(ctx, `
		UPDATE resources
		   SET status = 'active', paused_at = NULL
		 WHERE team_id = $1 AND status = 'paused'
	`, teamID)
	if err != nil {
		return 0, fmt.Errorf("models.ResumeAllTeamResources: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// TeamSlug returns the visible identifier the owner must echo back on
// DELETE /api/v1/team to confirm the destructive action. It is the
// team's name when set, otherwise "team-<first 8 chars of UUID>".
//
// Defense-in-depth: the caller must already hold a valid session, BE
// the team's owner, AND know the slug. Mistyping or copy-pasting the
// wrong slug short-circuits before any state change.
func TeamSlug(t *Team) string {
	if t.Name.Valid {
		if s := t.Name.String; s != "" {
			return s
		}
	}
	id := t.ID.String()
	if len(id) > 8 {
		id = id[:8]
	}
	return "team-" + id
}
