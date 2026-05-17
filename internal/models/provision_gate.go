package models

// provision_gate.go — atomic tier-cap enforcement for deployments + stacks.
//
// P5 (bug-hunt 2026-05-17): the deploy / stack / promote handlers used a
// check-then-act pair — CountActive*ByTeam followed by a separate
// Create* — with NOTHING serialising the two. Two concurrent
// POST /deploy/new (or /stacks/new, or /stacks/:slug/promote) for the
// same team both read the SAME stale count, both pass the per-tier cap,
// and both create → a paid-tier cap bypass.
//
// Fix: the count-check and the create now run inside ONE transaction that
// first takes a row lock on the team (SELECT id FROM teams WHERE id = $1
// FOR UPDATE). Postgres serialises every concurrent provision for that
// team on the team-row lock, so the second request blocks until the first
// commits and then sees the post-insert count. The lock is per-team, so
// provisions for DIFFERENT teams still run fully concurrently.
//
// The tier cap itself is NOT hardcoded here — the caller passes the limit
// it resolved from plans.Registry (per CLAUDE.md convention #3). limit < 0
// means "unlimited" (team tier) and skips the cap check entirely.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// dbExecutor is the subset of *sql.DB / *sql.Tx the model write+read
// helpers need. Declaring it lets CreateDeployment / CreateStack /
// CreateStackService / CountActive*ByTeam run identically against a plain
// connection OR inside a transaction — the transaction is what makes the
// P5 count+create atomic. *sql.DB and *sql.Tx both satisfy this, so every
// existing caller that passes *sql.DB keeps compiling unchanged.
type dbExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ErrDeploymentCapReached is returned by CreateDeploymentWithCap when the
// team already has >= limit active deployments. The handler maps this to
// a 402 with the deployment-limit agent_action.
var ErrDeploymentCapReached = errors.New("deployment cap reached for tier")

// ErrStackCapReached is returned by CreateStackWithCap / the promote-gate
// helper when the team already has >= limit active stacks. The handler
// maps this to a 402 with the stack-limit agent_action.
var ErrStackCapReached = errors.New("stack cap reached for tier")

// lockTeamRow takes a FOR UPDATE row lock on the team inside tx. Every
// concurrent provision for the same team serialises here. A missing team
// row surfaces as ErrTeamNotFound so the caller can 404 cleanly rather
// than create an orphan deployment/stack.
func lockTeamRow(ctx context.Context, tx *sql.Tx, teamID uuid.UUID) error {
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM teams WHERE id = $1 FOR UPDATE`, teamID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return &ErrTeamNotFound{ID: teamID}
	}
	if err != nil {
		return fmt.Errorf("lockTeamRow: %w", err)
	}
	return nil
}

// CreateDeploymentWithCap atomically enforces the per-tier deployments_apps
// cap and creates the deployment row. It is the race-free replacement for
// the handler doing CountActiveDeploymentsByTeam + CreateDeployment as two
// separate statements.
//
//	limit < 0  → unlimited (team tier); the cap check is skipped.
//	limit >= 0 → reject with ErrDeploymentCapReached when the team already
//	             has >= limit active deployments.
//
// The whole thing runs in one tx that locks the team row first, so two
// concurrent /deploy/new calls for the same team cannot both pass a stale
// count. The returned *Deployment is the freshly-inserted row.
func CreateDeploymentWithCap(ctx context.Context, db *sql.DB, limit int, p CreateDeploymentParams) (*Deployment, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateDeploymentWithCap: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockTeamRow(ctx, tx, p.TeamID); err != nil {
		return nil, err
	}

	if limit >= 0 {
		existing, err := CountActiveDeploymentsByTeam(ctx, tx, p.TeamID)
		if err != nil {
			return nil, err
		}
		if existing >= limit {
			return nil, ErrDeploymentCapReached
		}
	}

	saved, err := CreateDeployment(ctx, tx, p)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("CreateDeploymentWithCap: commit: %w", err)
	}
	return saved, nil
}

// StackWithServices is the result of CreateStackWithCap — the stack row
// plus every service row created alongside it, in the order the caller
// supplied them.
type StackWithServices struct {
	Stack    *Stack
	Services []*StackService
}

// CreateStackWithCap atomically enforces the per-tier stack cap and creates
// the stack + all of its service rows. Race-free replacement for the
// handler doing CountActiveStacksByTeam + CreateStack + CreateStackService
// as separate statements.
//
//	limit < 0  → unlimited; cap check skipped.
//	limit >= 0 → reject with ErrStackCapReached when the team already has
//	             >= limit active stacks.
//
// services carry a zero StackID — CreateStackWithCap fills in the freshly
// created stack's ID before inserting each one, so the caller does not
// have to know the ID up front.
//
// Anonymous stacks (CreateStackParams.TeamID == nil) carry no team and no
// tier cap; the caller passes limit < 0 and this function skips the team
// lock. They are already rate-limited by the fingerprint path.
func CreateStackWithCap(ctx context.Context, db *sql.DB, limit int, p CreateStackParams, services []CreateStackServiceParams) (*StackWithServices, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateStackWithCap: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock + cap only apply to team-owned stacks. Anonymous stacks have
	// no team row to lock and no per-tier cap.
	if p.TeamID != nil {
		if err := lockTeamRow(ctx, tx, *p.TeamID); err != nil {
			return nil, err
		}
		if limit >= 0 {
			existing, err := CountActiveStacksByTeam(ctx, tx, *p.TeamID)
			if err != nil {
				return nil, err
			}
			if existing >= limit {
				return nil, ErrStackCapReached
			}
		}
	}

	stack, err := CreateStack(ctx, tx, p)
	if err != nil {
		return nil, err
	}

	out := &StackWithServices{Stack: stack}
	for _, svc := range services {
		svc.StackID = stack.ID
		ss, err := CreateStackService(ctx, tx, svc)
		if err != nil {
			return nil, err
		}
		out.Services = append(out.Services, ss)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("CreateStackWithCap: commit: %w", err)
	}
	return out, nil
}

// CheckStackCapLocked is the promote-path gate: the /stacks/:slug/promote
// in-place re-promote branch creates a stack via its own multi-step flow
// (it copies image_ref-pinned service rows), so it cannot use
// CreateStackWithCap wholesale. Instead it runs its create work inside a
// caller-supplied tx and calls this helper FIRST, inside that same tx, to
// take the team lock + enforce the cap atomically with the create.
//
// limit < 0 skips the cap check. Returns ErrStackCapReached when over cap.
func CheckStackCapLocked(ctx context.Context, tx *sql.Tx, teamID uuid.UUID, limit int) error {
	if err := lockTeamRow(ctx, tx, teamID); err != nil {
		return err
	}
	if limit < 0 {
		return nil
	}
	existing, err := CountActiveStacksByTeam(ctx, tx, teamID)
	if err != nil {
		return err
	}
	if existing >= limit {
		return ErrStackCapReached
	}
	return nil
}
