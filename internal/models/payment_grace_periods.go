package models

// payment_grace_periods.go — failed-charge dunning state machine.
//
// One active row per team between the first failed Razorpay charge and
// either successful recovery or terminator-job execution at the 7-day
// expiry. Drives the worker's two periodic sweeps (reminder + terminator)
// and the billing webhook's idempotent grace-start path.
//
// State transitions (enforced by the application, not the DB):
//
//   <none> ─── CreatePaymentGracePeriod ────► active
//   active ─── MarkPaymentGraceRecovered ───► recovered
//   active ─── MarkPaymentGraceTerminated ──► terminated
//
// Once a row leaves 'active' it is read-only. The unique partial index
// (uq_payment_grace_team_active) means a second Create on the same team
// while a row is active hits the constraint — callers translate the
// unique-violation into a silent no-op (the grace clock has already
// started; webhook redeliveries must not double-trigger).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// PaymentGracePeriodGraceDays is the customer-facing grace window. The
// brief locks this to 7 days — change here in one place if product
// updates the policy. The terminator job's "expires_at < now()" sweep
// depends on this being a real duration, not a synthetic flag.
const PaymentGracePeriodGraceDays = 7

// Grace period status enum values. Stored as TEXT so a future
// 'admin_extended' / 'paused' status can ship without a column change,
// but writers MUST go through the constants here so a typo doesn't
// silently leak (e.g. "terminated " with a trailing space) — readers
// match on these exact strings.
const (
	PaymentGraceStatusActive     = "active"
	PaymentGraceStatusRecovered  = "recovered"
	PaymentGraceStatusTerminated = "terminated"
)

// ErrPaymentGraceAlreadyActive is the sentinel CreatePaymentGracePeriod
// returns when the partial-unique index fires — i.e. a row with
// status='active' already exists for the team. Callers (the Razorpay
// webhook handler) translate this into a no-op: the grace clock has
// already started, a redelivery of the same charge_failed event must
// not duplicate it.
var ErrPaymentGraceAlreadyActive = errors.New("models: payment grace period already active for team")

// pgUniqueViolation is the SQLSTATE Postgres returns when a unique
// constraint (including partial indexes) is violated. Centralised here
// rather than scattered across model files so a future migration to a
// different driver only has to touch one constant.
const pgUniqueViolation = "23505"

// PaymentGracePeriod mirrors one row of the payment_grace_periods table.
// Pointer-typed time fields are nullable per the schema:
//   - LastReminderAt is NULL until the first reminder fires.
//   - RecoveredAt is set iff Status == "recovered".
//   - TerminatedAt is set iff Status == "terminated".
type PaymentGracePeriod struct {
	ID              uuid.UUID
	TeamID          uuid.UUID
	SubscriptionID  string
	Status          string
	StartedAt       time.Time
	ExpiresAt       time.Time
	RemindersSent   int
	LastReminderAt  *time.Time
	RecoveredAt     *time.Time
	TerminatedAt    *time.Time
}

// CreatePaymentGracePeriodParams collects the inputs the Razorpay
// webhook handler hands to the model when a charge_failed event lands.
// ExpiresAt is the moment the terminator job will sweep this row — set
// to now() + PaymentGracePeriodGraceDays days at the call site so the
// model never has to reach for time.Now() (testable + deterministic).
type CreatePaymentGracePeriodParams struct {
	TeamID         uuid.UUID
	SubscriptionID string
	StartedAt      time.Time
	ExpiresAt      time.Time
}

// CreatePaymentGracePeriod inserts a new active grace row. Returns
// ErrPaymentGraceAlreadyActive when the partial-unique index trips
// (i.e. another active row already exists for the team) — the webhook
// handler treats this as "redelivery, no-op". Any other error bubbles
// as wrapped fmt.Errorf for the caller to log + alert on.
//
// Why we use the unique-violation as the idempotency signal rather than
// SELECT-then-INSERT: a concurrent webhook redelivery would race past a
// SELECT. The DB-enforced unique index is the only path that's
// concurrency-safe without a transaction-level advisory lock. The cost
// is one round-trip in the unhappy path — acceptable, this is webhook
// land, not a hot loop.
func CreatePaymentGracePeriod(ctx context.Context, db *sql.DB, p CreatePaymentGracePeriodParams) (*PaymentGracePeriod, error) {
	if p.TeamID == uuid.Nil {
		return nil, fmt.Errorf("models.CreatePaymentGracePeriod: team_id is required")
	}
	if strings.TrimSpace(p.SubscriptionID) == "" {
		return nil, fmt.Errorf("models.CreatePaymentGracePeriod: subscription_id is required")
	}
	if p.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("models.CreatePaymentGracePeriod: expires_at is required")
	}

	startedAt := p.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}

	g := &PaymentGracePeriod{}
	err := db.QueryRowContext(ctx, `
		INSERT INTO payment_grace_periods (team_id, subscription_id, status, started_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, team_id, subscription_id, status, started_at, expires_at, reminders_sent, last_reminder_at, recovered_at, terminated_at
	`, p.TeamID, p.SubscriptionID, PaymentGraceStatusActive, startedAt.UTC(), p.ExpiresAt.UTC()).Scan(
		&g.ID, &g.TeamID, &g.SubscriptionID, &g.Status, &g.StartedAt, &g.ExpiresAt,
		&g.RemindersSent, &g.LastReminderAt, &g.RecoveredAt, &g.TerminatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && string(pqErr.Code) == pgUniqueViolation {
			return nil, ErrPaymentGraceAlreadyActive
		}
		return nil, fmt.Errorf("models.CreatePaymentGracePeriod: %w", err)
	}
	return g, nil
}

// GetActivePaymentGracePeriod returns the team's currently-active grace
// row, or (nil, nil) when none exists. Used by the Razorpay webhook
// handler to short-circuit "already in grace" before attempting the
// idempotent INSERT — a slightly nicer ergonomic than catching the
// unique-violation, though both paths are correct.
//
// nil/nil is the "not found" signal so callers don't have to import
// sql.ErrNoRows in handler land. The unique partial index guarantees at
// most one row matches.
func GetActivePaymentGracePeriod(ctx context.Context, db *sql.DB, teamID uuid.UUID) (*PaymentGracePeriod, error) {
	if teamID == uuid.Nil {
		return nil, fmt.Errorf("models.GetActivePaymentGracePeriod: team_id is required")
	}
	g := &PaymentGracePeriod{}
	err := db.QueryRowContext(ctx, `
		SELECT id, team_id, subscription_id, status, started_at, expires_at,
		       reminders_sent, last_reminder_at, recovered_at, terminated_at
		  FROM payment_grace_periods
		 WHERE team_id = $1 AND status = $2
		 LIMIT 1
	`, teamID, PaymentGraceStatusActive).Scan(
		&g.ID, &g.TeamID, &g.SubscriptionID, &g.Status, &g.StartedAt, &g.ExpiresAt,
		&g.RemindersSent, &g.LastReminderAt, &g.RecoveredAt, &g.TerminatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("models.GetActivePaymentGracePeriod: %w", err)
	}
	return g, nil
}

// MarkPaymentGraceRecovered flips the team's active grace row to
// status='recovered' and stamps recovered_at. Returns (true, nil) when
// a row was updated, (false, nil) when no active grace was in flight
// (i.e. a subscription.charged event arrived without a prior
// charge_failed — the normal happy-path renewal). Errors are surfaced
// as wrapped fmt.Errorf.
//
// The WHERE predicate filters on status='active' so a redelivered
// charged-webhook can't accidentally flip a 'terminated' row back to
// 'recovered'. Once-terminated grace rows are read-only — the customer's
// resources have already been soft-deleted in worker land and the
// resurrection path is admin-only.
func MarkPaymentGraceRecovered(ctx context.Context, db *sql.DB, teamID uuid.UUID, recoveredAt time.Time) (bool, error) {
	if teamID == uuid.Nil {
		return false, fmt.Errorf("models.MarkPaymentGraceRecovered: team_id is required")
	}
	if recoveredAt.IsZero() {
		recoveredAt = time.Now().UTC()
	}
	res, err := db.ExecContext(ctx, `
		UPDATE payment_grace_periods
		   SET status = $1, recovered_at = $2
		 WHERE team_id = $3 AND status = $4
	`, PaymentGraceStatusRecovered, recoveredAt.UTC(), teamID, PaymentGraceStatusActive)
	if err != nil {
		return false, fmt.Errorf("models.MarkPaymentGraceRecovered: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.MarkPaymentGraceRecovered rows_affected: %w", err)
	}
	return n > 0, nil
}

// TerminateAllPaymentGracePeriodsForTeam flips EVERY active grace row for
// a team to status='terminated' and stamps terminated_at. Returns the
// number of rows actually transitioned. Unlike MarkPaymentGraceTerminated
// (which targets the single active row produced by the partial-unique
// index), this is the bulk endpoint the internal-terminate handler uses
// — the brief specifies "Mark every dunning row for this team as
// status='terminated'", which is conceptually a sweep across the team's
// dunning history. In practice the unique partial index limits this to
// at most one row at any given instant, but writing the SQL as an
// unbounded UPDATE … WHERE status='active' makes the idempotency
// contract obvious: a second call (or a partial earlier termination)
// converges to "no active rows left."
//
// A return of 0 means there was nothing to terminate — either the team
// never entered grace, or a prior termination already swept the row.
// Callers treat 0 as "noop, continue" rather than an error.
func TerminateAllPaymentGracePeriodsForTeam(ctx context.Context, db *sql.DB, teamID uuid.UUID, terminatedAt time.Time) (int64, error) {
	if teamID == uuid.Nil {
		return 0, fmt.Errorf("models.TerminateAllPaymentGracePeriodsForTeam: team_id is required")
	}
	if terminatedAt.IsZero() {
		terminatedAt = time.Now().UTC()
	}
	res, err := db.ExecContext(ctx, `
		UPDATE payment_grace_periods
		   SET status = $1, terminated_at = $2
		 WHERE team_id = $3 AND status = $4
	`, PaymentGraceStatusTerminated, terminatedAt.UTC(), teamID, PaymentGraceStatusActive)
	if err != nil {
		return 0, fmt.Errorf("models.TerminateAllPaymentGracePeriodsForTeam: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("models.TerminateAllPaymentGracePeriodsForTeam rows_affected: %w", err)
	}
	return n, nil
}

// HasTerminatedPaymentGracePeriod returns true iff at least one
// terminated-status row exists for the team. Drives the
// internal-terminate handler's idempotency check: if a previous
// terminate already ran (worker retried, network blip, etc.), the
// second call returns 200 noop without re-pausing resources or
// re-cancelling Razorpay.
//
// We deliberately key idempotency off the dunning row (not off a
// hypothetical teams.status column) — the dunning row IS the audit
// trail for "this team was terminated by the grace-expiry sweep,"
// and there is no separate teams.status column in the schema.
func HasTerminatedPaymentGracePeriod(ctx context.Context, db *sql.DB, teamID uuid.UUID) (bool, error) {
	if teamID == uuid.Nil {
		return false, fmt.Errorf("models.HasTerminatedPaymentGracePeriod: team_id is required")
	}
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		  FROM payment_grace_periods
		 WHERE team_id = $1 AND status = $2
	`, teamID, PaymentGraceStatusTerminated).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("models.HasTerminatedPaymentGracePeriod: %w", err)
	}
	return n > 0, nil
}

// MarkPaymentGraceTerminated is the destructive end-state. Called by
// the worker's terminator job (separate PR) when expires_at < now()
// and no recovery happened. The actual destructive work — Razorpay
// cancel call + soft-delete of team resources — lives in the worker;
// this model call only flips the state row, so the API repo can ship
// the trigger + state machine independently of the destructive work.
//
// Same activeness predicate as MarkPaymentGraceRecovered: only an
// 'active' row transitions to 'terminated'. A double-terminator-run is
// a no-op.
func MarkPaymentGraceTerminated(ctx context.Context, db *sql.DB, teamID uuid.UUID, terminatedAt time.Time) (bool, error) {
	if teamID == uuid.Nil {
		return false, fmt.Errorf("models.MarkPaymentGraceTerminated: team_id is required")
	}
	if terminatedAt.IsZero() {
		terminatedAt = time.Now().UTC()
	}
	res, err := db.ExecContext(ctx, `
		UPDATE payment_grace_periods
		   SET status = $1, terminated_at = $2
		 WHERE team_id = $3 AND status = $4
	`, PaymentGraceStatusTerminated, terminatedAt.UTC(), teamID, PaymentGraceStatusActive)
	if err != nil {
		return false, fmt.Errorf("models.MarkPaymentGraceTerminated: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("models.MarkPaymentGraceTerminated rows_affected: %w", err)
	}
	return n > 0, nil
}
