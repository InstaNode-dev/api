package models

// pending_propagation.go — model layer for the pending_propagations table
// (migration 058). The api WRITES rows here from handleSubscriptionCharged
// after the atomic upgrade transaction has committed; the worker READS and
// DISPATCHES them via its propagation_runner job. The api never reads back —
// the surface here is INSERT-only.
//
// Why a separate file (not folded into team.go or audit_log.go):
//
//   * audit_log is append-only; pending_propagations carries mutable state
//     (attempts, next_attempt_at, applied_at, failed_at, last_error). They
//     are different lifecycles.
//   * team.go owns plan_tier transitions inside the atomic upgrade tx. The
//     propagation enqueue happens AFTER the tx commits (it must not roll
//     back the user-visible upgrade on its own insert failure), so it
//     intentionally lives outside the tx-bearing functions in team.go.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// EnqueuePendingPropagation inserts one row into pending_propagations.
//
// Caller contract: this is BEST-EFFORT and runs OUTSIDE the upgrade tx. If
// the INSERT fails, the caller MUST log loudly but MUST NOT fail the
// containing operation (the user-visible upgrade has already committed at
// this point — failing the webhook would cause Razorpay to redeliver and
// re-apply an already-applied upgrade, and worse, the entitlement_reconciler
// is still the eventually-consistent backstop). See billing.go's call site
// for the canonical logging shape.
//
// Returns the new row's id on success. The id is informational: callers do
// not typically need to surface it (the worker's propagation_runner picks
// rows up by predicate, not by id). The id IS logged so an operator
// joining audit_log → pending_propagations has a stable identifier.
//
// target_tier may be empty string for non-tier kinds — it is written to the
// nullable target_tier column as SQL NULL when empty.
//
// payload may be nil — it is written as the column DEFAULT '{}'::jsonb.
func EnqueuePendingPropagation(ctx context.Context, db DBExec, kind string, teamID uuid.UUID, targetTier string, payload []byte) (uuid.UUID, error) {
	if kind == "" {
		return uuid.Nil, fmt.Errorf("EnqueuePendingPropagation: kind required")
	}
	if teamID == uuid.Nil {
		return uuid.Nil, fmt.Errorf("EnqueuePendingPropagation: team_id required")
	}

	var (
		tierArg    interface{} = nil
		payloadArg interface{} = []byte(`{}`)
	)
	if targetTier != "" {
		tierArg = targetTier
	}
	if len(payload) > 0 {
		payloadArg = payload
	}

	var id uuid.UUID
	if err := db.QueryRowContext(ctx, `
		INSERT INTO pending_propagations (kind, team_id, target_tier, payload)
		VALUES ($1, $2::uuid, $3, $4::jsonb)
		RETURNING id
	`, kind, teamID, tierArg, payloadArg).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("EnqueuePendingPropagation: insert: %w", err)
	}
	return id, nil
}

// DBExec is the narrow surface EnqueuePendingPropagation needs from a DB
// handle — both *sql.DB and *sql.Tx satisfy it. Declared locally (not in
// a shared types file) so callers can pass either without re-typing the
// interface at the call site. A future caller that wants to fold the
// enqueue into a larger tx can pass *sql.Tx; today's only caller
// (handleSubscriptionCharged) passes *sql.DB because the enqueue
// runs AFTER the upgrade tx commits — see the file header.
type DBExec interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}
