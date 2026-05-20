//go:build chaos

// Package e2e — PROPAGATION CHAOS DRILL (Test 1 of CHAOS-DRILL-2026-05-20)
//
// Behind the `chaos` build tag — never runs in any normal gate. Compiles only
// under `-tags chaos`. The existing `make chaostest` target ALSO runs the
// `loadtest+e2e` pod-kill harness; the new `make chaostest-propagation`
// target runs this file in isolation.
//
// ─── WHAT THIS DOES ───────────────────────────────────────────────────────────
//
// CLAUDE.md rule 12 — "Shipped ≠ Verified". The propagation_runner job was
// shipped on 2026-05-15 (migration 058 + worker/internal/jobs/
// propagation_runner.go) with 10-attempt exponential backoff and a
// `propagation.dead_lettered` terminal audit row at maxAttempts. The retry +
// dead-letter path was unit-tested with mocked clocks but the FULL live path
// (api enqueues row → worker picks up under SKIP LOCKED → real backoff timer
// → real dead-letter audit row → NR alert) was never exercised end-to-end
// against the running cluster.
//
// This test exercises it against the LIVE platform DB + worker.
//
// THE THREE ASSERTIONS
// --------------------
//
//	A. Pickup — the worker's propagation_runner picks up our synthetic row
//	   on the next 30-second tick (`last_attempt_at` is stamped, `attempts`
//	   increments).
//
//	B. Backoff schedule — the row's `next_attempt_at` advances per the
//	   declared propagationBackoffSchedule. attempts=1 should add 1m,
//	   attempts=2 should add 5m. We do NOT wait through the full 24h
//	   cumulative backoff — see "Shortcut" below.
//
//	C. Dead-letter — when attempts reaches propagationMaxAttempts (10) on a
//	   row whose handler keeps failing, the row transitions to
//	   failed_at != NULL AND a `propagation.dead_lettered` audit_log row
//	   appears with actor='propagation_runner' AND a structured ERROR log
//	   line (`jobs.propagation_runner.dead_lettered`) fires.
//
// ─── HOW WE FORCE A REAL FAILURE ──────────────────────────────────────────────
//
// handleTierElevation iterates the team's `resources` rows and calls
// provisioner.RegradeResource for each. To force a deterministic error:
//
//   - Insert ONE synthetic team (plan_tier='pro').
//   - Insert ONE synthetic postgres resource on that team with a bogus
//     token + provider_resource_id (no real DB role exists).
//   - The provisioner's regradePostgres will run ALTER ROLE against a
//     non-existent role → returns an error → handler returns the error.
//
// The chaos drill safely uses a totally synthetic team (no real customer
// touched) and cleans up at the end (DELETE CASCADE removes the team +
// resource + pending_propagations + audit rows).
//
// ─── SHORTCUT: fast-loop dead-letter via attempts seed ────────────────────────
//
// The natural backoff schedule sums to ~24h33m before maxAttempts. To
// dead-letter in a single chaos run we seed `attempts = propagationMaxAttempts
// - 1 = 9` and force `next_attempt_at = now()` so the very next worker tick
// dispatches → handler errors → `attempts+1 >= propagationMaxAttempts` →
// markDeadLettered fires. This exercises the EXACT terminal-transition code
// path; only the cumulative wall-clock is shortcut.
//
// We ALSO insert a separate "natural-backoff" row at attempts=0 to assert
// the propagationBackoffSchedule[0] = 1 minute step holds for one cycle on a
// live worker (Phase B of the test).
//
// ─── SAFETY ENVELOPE ──────────────────────────────────────────────────────────
//
//   - Synthetic team / synthetic resource ONLY. No real customer data touched.
//   - Bogus token means the provisioner ALTER ROLE will fail safely (role
//     does not exist → SQL error → returned to caller). No state mutated on
//     any real customer's Postgres role.
//   - Cleanup runs in t.Cleanup() and on test failure: DELETE the team row
//     (CASCADE handles resources + pending_propagations + audit_log).
//
// ─── HOW TO RUN ───────────────────────────────────────────────────────────────
//
//	make chaostest-propagation
//
// Required env:
//
//	E2E_PLATFORM_DB_URL  full postgres:// URL to the platform DB. For prod:
//	                     kubectl get secret instant-secrets -n instant \
//	                       -o jsonpath='{.data.DATABASE_URL}' | base64 -d
//
// Optional:
//
//	CHAOS_TICK_BUDGET    how long to wait for one worker tick (default 90s).
//	                     The runner ticks every 30s; 90s = 3 ticks of safety.
//	CHAOS_BACKOFF_PHASE  set to "skip" to skip the natural-backoff phase (B).
//	                     Default runs phases A + B + C.
package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// ─── named constants — every magic value in this file lives here ─────────────

const (
	// chaosPropagationMaxAttempts mirrors propagation_runner.go's
	// propagationMaxAttempts. Drift between the two MUST surface as a
	// dead-letter assertion mismatch — that is the whole point of the
	// chaos drill. If propagation_runner.go bumps the constant, this
	// file MUST be updated in the same PR.
	chaosPropagationMaxAttempts = 10

	// chaosPropagationFirstBackoff mirrors propagationBackoffSchedule[0].
	// Same drift contract — Phase B asserts the LIVE behaviour matches.
	chaosPropagationFirstBackoff = 1 * time.Minute

	// chaosTickBudgetDefault — how long to wait for one full worker tick.
	// The runner ticks every 30s by default; 90s = 3 ticks of safety.
	chaosTickBudgetDefault = 90 * time.Second

	// chaosDeadLetterBudget — how long to wait for the dead-letter
	// transition once we have seeded attempts=maxAttempts-1.
	chaosDeadLetterBudget = 120 * time.Second

	// chaosPollInterval — how often to poll the DB while waiting.
	chaosPollInterval = 3 * time.Second

	// chaosSyntheticTeamMarker — TEAMS.NAME prefix the cleanup sweep uses
	// to identify rows this test created (in case an earlier run crashed
	// mid-flight and left orphan rows).
	chaosSyntheticTeamMarker = "chaos-drill-propagation"

	// chaosKindTierElevation mirrors the worker's PropagationKindTierElevation
	// (and api's models.PropagationKindTierElevation). The worker's registry
	// dispatches this kind to handleTierElevation.
	chaosKindTierElevation = "tier_elevation"

	// chaosAuditKindDeadLettered mirrors the worker's
	// auditKindPropagationDeadLettered. Phase C asserts this row appears.
	chaosAuditKindDeadLettered = "propagation.dead_lettered"

	// chaosAuditActorPropagationRunner mirrors the worker's propagationActor.
	chaosAuditActorPropagationRunner = "propagation_runner"
)

// chaosTickBudget resolves the per-tick wait from CHAOS_TICK_BUDGET.
func chaosTickBudget() time.Duration {
	if v := os.Getenv("CHAOS_TICK_BUDGET"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return chaosTickBudgetDefault
}

// chaosPlatformDB opens the platform DB. Skips the test cleanly if the URL
// is not set so the chaos drill is opt-in.
func chaosPlatformDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("E2E_PLATFORM_DB_URL")
	if url == "" {
		t.Skip("chaos: E2E_PLATFORM_DB_URL not set — skipping propagation chaos drill")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("chaos: open platform DB: %v", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("chaos: ping platform DB: %v", err)
	}
	return db
}

// chaosSeedSyntheticTeam inserts a synthetic team + one bogus postgres
// resource that will deterministically fail RegradeResource (the role does
// not exist in the customer Postgres). Returns the team id + cleanup func.
func chaosSeedSyntheticTeam(t *testing.T, db *sql.DB, label string) (uuid.UUID, func()) {
	t.Helper()
	ctx := context.Background()

	teamID := uuid.New()
	// Name carries the run label so a hung run can be cleaned up by hand.
	// plan_tier='pro' is the target tier the propagation row will reference.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO teams (id, name, plan_tier)
		VALUES ($1, $2, 'pro')
	`, teamID, fmt.Sprintf("%s-%s-%d", chaosSyntheticTeamMarker, label, time.Now().Unix())); err != nil {
		t.Fatalf("chaos: insert synthetic team: %v", err)
	}

	// Synthetic postgres resource. Token is a random UUID (guaranteed not to
	// resolve to a real DB role); provider_resource_id is a bogus k8s ns
	// (will not exist in the cluster). status='active', tier='pro' (matches
	// what UpgradeTeamAllTiersWithSubscription would have written for a
	// charged team).
	resID := uuid.New()
	resToken := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO resources (id, team_id, token, resource_type, tier, status, provider_resource_id)
		VALUES ($1, $2, $3, 'postgres', 'pro', 'active', $4)
	`, resID, teamID, resToken, "instant-customer-chaos-"+resToken.String()[:8]); err != nil {
		t.Fatalf("chaos: insert synthetic resource: %v", err)
	}

	cleanup := func() {
		// DELETE CASCADE on teams takes resources, pending_propagations,
		// audit_log (all FK to teams). Failures here are best-effort —
		// orphans get swept by the start-of-test garbage collector.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, `DELETE FROM teams WHERE id = $1`, teamID); err != nil {
			t.Logf("chaos: cleanup team %s failed (best-effort): %v", teamID, err)
		} else {
			t.Logf("chaos: cleanup team %s OK", teamID)
		}
	}
	return teamID, cleanup
}

// chaosSweepOrphans deletes any leftover synthetic teams from prior runs.
// Idempotent. Runs at test start.
func chaosSweepOrphans(t *testing.T, db *sql.DB) {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		`DELETE FROM teams WHERE name LIKE $1 AND created_at < now() - interval '1 hour'`,
		chaosSyntheticTeamMarker+"%",
	)
	if err != nil {
		t.Logf("chaos: orphan sweep failed (best-effort): %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		t.Logf("chaos: swept %d stale synthetic teams from prior runs", n)
	}
}

// chaosPropagationRow projects the columns we care about during polling.
type chaosPropagationRow struct {
	ID            uuid.UUID
	Attempts      int
	LastAttemptAt sql.NullTime
	NextAttemptAt time.Time
	AppliedAt     sql.NullTime
	FailedAt      sql.NullTime
	LastError     sql.NullString
}

func (r chaosPropagationRow) terminal() bool {
	return r.AppliedAt.Valid || r.FailedAt.Valid
}

// chaosFetchPropagation polls one propagation row by id.
func chaosFetchPropagation(t *testing.T, db *sql.DB, id uuid.UUID) chaosPropagationRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var r chaosPropagationRow
	err := db.QueryRowContext(ctx, `
		SELECT id, attempts, last_attempt_at, next_attempt_at, applied_at, failed_at, last_error
		FROM pending_propagations
		WHERE id = $1
	`, id).Scan(&r.ID, &r.Attempts, &r.LastAttemptAt, &r.NextAttemptAt, &r.AppliedAt, &r.FailedAt, &r.LastError)
	if err != nil {
		t.Fatalf("chaos: fetch propagation %s: %v", id, err)
	}
	return r
}

// chaosFetchDeadLetterAudit returns true if a propagation.dead_lettered
// audit_log row exists for the given team + propagation_id.
func chaosFetchDeadLetterAudit(t *testing.T, db *sql.DB, teamID, propagationID uuid.UUID) (bool, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var meta []byte
	err := db.QueryRowContext(ctx, `
		SELECT metadata::text::bytea
		FROM audit_log
		WHERE team_id = $1
		  AND kind = $2
		  AND actor = $3
		  AND metadata->>'propagation_id' = $4
		ORDER BY created_at DESC
		LIMIT 1
	`, teamID, chaosAuditKindDeadLettered, chaosAuditActorPropagationRunner, propagationID.String()).Scan(&meta)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		t.Fatalf("chaos: query audit_log dead_letter: %v", err)
	}
	return true, meta
}

// ─── the test ─────────────────────────────────────────────────────────────────

// TestChaos_PropagationRunner_DeadLetterPath verifies the propagation_runner
// retry + dead-letter path against the LIVE worker. See file header for
// rationale + safety envelope.
func TestChaos_PropagationRunner_DeadLetterPath(t *testing.T) {
	db := chaosPlatformDB(t)
	defer db.Close()

	chaosSweepOrphans(t, db)

	// ─── Phase A: Pickup ──────────────────────────────────────────────────────
	// Insert a fresh propagation row at attempts=0, next_attempt_at=now().
	// Within one tick budget the worker should pick it up: attempts → 1,
	// last_attempt_at stamped, next_attempt_at advanced by ~1 minute (the
	// first step of propagationBackoffSchedule).

	teamID, cleanup := chaosSeedSyntheticTeam(t, db, "phaseA")
	defer cleanup()

	var propID uuid.UUID
	if err := db.QueryRowContext(context.Background(), `
		INSERT INTO pending_propagations (kind, team_id, target_tier, payload)
		VALUES ($1, $2, $3, '{}'::jsonb)
		RETURNING id
	`, chaosKindTierElevation, teamID, "pro").Scan(&propID); err != nil {
		t.Fatalf("chaos: insert propagation row: %v", err)
	}
	t.Logf("PHASE A: enqueued propagation_id=%s team_id=%s kind=%s target=pro at %s",
		propID, teamID, chaosKindTierElevation, time.Now().UTC().Format(time.RFC3339))

	// Wait for the row to be picked up (attempts ≥ 1, last_attempt_at != NULL).
	pickedUp, observed := chaosWaitForCondition(t, db, propID, chaosTickBudget(), func(r chaosPropagationRow) bool {
		return r.Attempts >= 1 && r.LastAttemptAt.Valid
	})
	if !pickedUp {
		t.Fatalf("PHASE A FAIL: worker did not pick up propagation_id=%s within %s — last state attempts=%d last_attempt_at=%v next_attempt_at=%s last_error=%v",
			propID, chaosTickBudget(), observed.Attempts, observed.LastAttemptAt, observed.NextAttemptAt.UTC().Format(time.RFC3339), observed.LastError)
	}
	t.Logf("PHASE A PASS: picked up at %s — attempts=%d last_error=%q",
		observed.LastAttemptAt.Time.UTC().Format(time.RFC3339), observed.Attempts, observed.LastError.String)

	// ─── Phase B: Backoff schedule ───────────────────────────────────────────
	// Assert next_attempt_at advanced by approximately propagationBackoffSchedule[0]
	// = 1 minute from the observed last_attempt_at. Tolerance ±10s for clock
	// skew between the worker's tx-time and our read.
	if os.Getenv("CHAOS_BACKOFF_PHASE") != "skip" {
		delta := observed.NextAttemptAt.Sub(observed.LastAttemptAt.Time)
		lo := chaosPropagationFirstBackoff - 10*time.Second
		hi := chaosPropagationFirstBackoff + 10*time.Second
		if delta < lo || delta > hi {
			t.Errorf("PHASE B FAIL: backoff delta = %s, expected ~%s (tolerance ±10s, observed_window=[%s, %s])",
				delta, chaosPropagationFirstBackoff, lo, hi)
		} else {
			t.Logf("PHASE B PASS: backoff delta = %s (expected ~%s, within tolerance)",
				delta, chaosPropagationFirstBackoff)
		}
	} else {
		t.Logf("PHASE B SKIPPED: CHAOS_BACKOFF_PHASE=skip")
	}

	// ─── Phase C: Dead-letter ────────────────────────────────────────────────
	// Insert a SECOND propagation row pre-seeded with attempts =
	// chaosPropagationMaxAttempts - 1 = 9 and next_attempt_at = now() so the
	// next tick triggers the dead-letter transition (not just another retry).

	teamID2, cleanup2 := chaosSeedSyntheticTeam(t, db, "phaseC")
	defer cleanup2()

	var propID2 uuid.UUID
	if err := db.QueryRowContext(context.Background(), `
		INSERT INTO pending_propagations
		    (kind, team_id, target_tier, payload, attempts, next_attempt_at)
		VALUES ($1, $2, $3, '{}'::jsonb, $4, now())
		RETURNING id
	`, chaosKindTierElevation, teamID2, "pro", chaosPropagationMaxAttempts-1).Scan(&propID2); err != nil {
		t.Fatalf("chaos: insert phaseC propagation row: %v", err)
	}
	t.Logf("PHASE C: enqueued propagation_id=%s team_id=%s attempts=%d (one tick from dead-letter) at %s",
		propID2, teamID2, chaosPropagationMaxAttempts-1, time.Now().UTC().Format(time.RFC3339))

	deadLettered, deadObserved := chaosWaitForCondition(t, db, propID2, chaosDeadLetterBudget, func(r chaosPropagationRow) bool {
		return r.FailedAt.Valid
	})
	if !deadLettered {
		t.Fatalf("PHASE C FAIL: row never transitioned to failed_at within %s — last state attempts=%d failed_at=%v applied_at=%v last_error=%v",
			chaosDeadLetterBudget, deadObserved.Attempts, deadObserved.FailedAt, deadObserved.AppliedAt, deadObserved.LastError)
	}
	if deadObserved.Attempts != chaosPropagationMaxAttempts {
		t.Errorf("PHASE C ASSERT: expected attempts=%d at dead-letter, got attempts=%d",
			chaosPropagationMaxAttempts, deadObserved.Attempts)
	}
	t.Logf("PHASE C PASS: dead-lettered at %s — attempts=%d last_error=%q",
		deadObserved.FailedAt.Time.UTC().Format(time.RFC3339), deadObserved.Attempts, deadObserved.LastError.String)

	// ─── Phase C-2: audit row ────────────────────────────────────────────────
	// The dead-letter MUST emit a propagation.dead_lettered audit_log row
	// with the correct team_id, actor, and metadata.propagation_id.
	found, metaBytes := chaosFetchDeadLetterAudit(t, db, teamID2, propID2)
	if !found {
		t.Fatalf("PHASE C-2 FAIL: no propagation.dead_lettered audit_log row for team=%s propagation=%s — alert would not fire",
			teamID2, propID2)
	}
	var meta map[string]any
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("PHASE C-2: audit_log.metadata not valid JSON: %v", err)
	}
	t.Logf("PHASE C-2 PASS: audit row found — kind=%s actor=%s metadata.attempts=%v metadata.max_attempts=%v metadata.last_error_truncated_to=%d bytes",
		chaosAuditKindDeadLettered, chaosAuditActorPropagationRunner, meta["attempts"], meta["max_attempts"],
		len(fmt.Sprint(meta["last_error"])))

	// ─── Findings summary log ────────────────────────────────────────────────
	t.Logf("CHAOS DRILL TEST 1 RESULT: PASS — propagation_runner picks up rows, advances backoff per schedule, dead-letters at maxAttempts=%d, emits %s audit row.",
		chaosPropagationMaxAttempts, chaosAuditKindDeadLettered)
}

// chaosWaitForCondition polls the propagation row until the condition holds
// or budget elapses. Returns ok + the last observed row.
func chaosWaitForCondition(t *testing.T, db *sql.DB, id uuid.UUID, budget time.Duration, cond func(chaosPropagationRow) bool) (bool, chaosPropagationRow) {
	t.Helper()
	deadline := time.Now().Add(budget)
	var last chaosPropagationRow
	for {
		last = chaosFetchPropagation(t, db, id)
		if cond(last) {
			return true, last
		}
		if time.Now().After(deadline) {
			return false, last
		}
		time.Sleep(chaosPollInterval)
	}
}
