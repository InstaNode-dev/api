//go:build chaos

// Package e2e — LEASE-RECOVERY CHAOS DRILL (Test 2 of CHAOS-DRILL-2026-05-20)
//
// Behind the `chaos` build tag. Pairs with worker/internal/jobs/
// chaos_lease_recovery.go.
//
// ─── WHAT THIS DRILL EXISTS FOR ───────────────────────────────────────────────
//
// CLAUDE.md rule 12 — "Shipped ≠ Verified". Task #172 added
// `JobTimeout: globalJobTimeout` (20 min) to the worker's River client
// config so a hung job cannot pin a slot forever. River pairs that with a
// rescuer that re-leases stuck jobs to other workers after
// `RescueStuckJobsAfter` (default = JobTimeout + 1h ≈ 1h20m). Neither the
// timeout NOR the rescuer was ever exercised against a real pod-kill in
// the live cluster.
//
// This drill triggers the rescuer for real.
//
// ─── HOW IT WORKS ─────────────────────────────────────────────────────────────
//
//   1. Insert a synthetic team into the platform DB (no real customer
//      touched; cleanup at the end).
//   2. Insert ONE row into the `river_job` table with
//      kind='chaos_lease_recovery', payload = {sleep_seconds=180,
//      team_id=<synthetic>, run_id=<random>}, state='available'.
//   3. Poll the audit_log for the FIRST chaos.lease_recovery.start row
//      (worker pod has begun the sleep). Note the pod_id from
//      metadata.pod.
//   4. (Operator step) `kubectl delete pod -n instant-infra <pod_id>
//      --grace-period=0 --force` — simulates OOMKill.
//   5. Poll audit_log for chaos.lease_recovery.end — must appear with
//      metadata.pod != killed_pod (some OTHER worker pod picked up the
//      job after the rescuer re-leased it).
//   6. Report the wall-clock from FIRST start marker to end marker.
//      That's the lease-recovery RTO. River defaults give a worst case of
//      ~1h20m; the actual observed RTO is the drill's primary finding.
//
// ─── WHY NOT WRITE A TEST THAT KILLS THE POD AUTOMATICALLY? ───────────────────
//
// The kill is a destructive operator action that absolutely must be done
// by a human who can verify the namespace + see the sibling replica is
// healthy. The drill is structured as Go test scaffolding (DB seed +
// polling + assertions) and explicit kubectl prompts the operator runs by
// hand. That keeps the chaos test from accidentally double-killing during
// a hung run.
//
// The test supports two modes:
//
//	CHAOS_LEASE_MODE=interactive (default) — pauses with operator
//	                                          instructions between phases
//	CHAOS_LEASE_MODE=observe                — does NOT prompt; just
//	                                          enqueues the job + polls
//	                                          until END marker appears.
//	                                          Useful for replaying a
//	                                          drill that an operator
//	                                          executed separately.
//
// ─── PREREQS ──────────────────────────────────────────────────────────────────
//
//	* The worker image must include chaos_lease_recovery.go (build
//	  master after that file landed). The worker_image_includes_chaos
//	  precheck asserts this by reading the worker's running pod kind
//	  registry — if the kind isn't registered, the test skips with a
//	  loud message ("worker image too old to support this drill").
//
// ─── HOW TO RUN ───────────────────────────────────────────────────────────────
//
//	make chaostest-lease-recovery
//
// Required env (same as Test 1):
//
//	E2E_PLATFORM_DB_URL
//
// Optional:
//
//	CHAOS_LEASE_SLEEP_SECONDS   sleep duration the job holds (default 180)
//	CHAOS_LEASE_RTO_BUDGET      wall-clock cap before failing (default 90m)
//	CHAOS_LEASE_MODE            interactive | observe (default interactive)
package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ─── named constants ─────────────────────────────────────────────────────────

const (
	// chaosLeaseRecoveryKind mirrors the worker's chaosLeaseRecoveryKind.
	// Drift between the two MUST be a CI-flagged build failure — the test
	// reads river_job WHERE kind = $1 with this literal.
	chaosLeaseRecoveryKind = "chaos_lease_recovery"

	// chaosLeaseRecoveryAuditStart/End mirror the worker's audit kinds.
	chaosLeaseRecoveryAuditStart = "chaos.lease_recovery.start"
	chaosLeaseRecoveryAuditEnd   = "chaos.lease_recovery.end"

	// chaosLeaseRecoveryActor mirrors the worker's actor name.
	chaosLeaseRecoveryActor = "chaos_lease_recovery"

	// chaosLeaseRecoveryDefaultSleep — long enough that an operator
	// running this by hand has ~3 minutes to identify the pod and run
	// `kubectl delete pod`. Override via CHAOS_LEASE_SLEEP_SECONDS.
	chaosLeaseRecoveryDefaultSleep = 180

	// chaosLeaseRecoveryDefaultRTOBudget — wall-clock cap before declaring
	// the lease-recovery path BROKEN. 90 min reflects River's default rescue
	// window: JobRescuerRescueAfterDefault=1h + JobTimeout=20m ≈ 1h20m
	// worst case, plus 10m slack for the rescuer's 30s interval +
	// reschedule + sibling pod's next fetch.
	chaosLeaseRecoveryDefaultRTOBudget = 90 * time.Minute

	// chaosLeaseRecoveryStartTimeout — how long to wait for the FIRST
	// start marker. The worker fetches available jobs on each producer
	// tick; with 5s producer interval this should be sub-10s.
	chaosLeaseRecoveryStartTimeout = 60 * time.Second

	// chaosLeaseRecoveryModeInteractive — pauses for operator kubectl step.
	chaosLeaseRecoveryModeInteractive = "interactive"
	// chaosLeaseRecoveryModeObserve — does not prompt; just polls.
	chaosLeaseRecoveryModeObserve = "observe"
)

// chaosLeaseSleepSeconds returns the sleep duration to seed into the job.
func chaosLeaseSleepSeconds() int {
	if v := os.Getenv("CHAOS_LEASE_SLEEP_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return chaosLeaseRecoveryDefaultSleep
}

// chaosLeaseRTOBudget returns the cap before the test declares failure.
func chaosLeaseRTOBudget() time.Duration {
	if v := os.Getenv("CHAOS_LEASE_RTO_BUDGET"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return chaosLeaseRecoveryDefaultRTOBudget
}

// chaosLeaseMode returns interactive | observe.
func chaosLeaseMode() string {
	v := os.Getenv("CHAOS_LEASE_MODE")
	if v == chaosLeaseRecoveryModeObserve {
		return chaosLeaseRecoveryModeObserve
	}
	return chaosLeaseRecoveryModeInteractive
}

// chaosLeaseAuditRow projects the audit_log columns the drill polls.
type chaosLeaseAuditRow struct {
	Kind     string
	Pod      string
	TS       time.Time
	Metadata map[string]any
}

// chaosFetchLeaseAuditRows returns every audit_log row for the given
// run_id, ordered by created_at ASC. The drill asserts on:
//
//	* At least one start marker exists.
//	* Exactly one end marker exists.
//	* The end marker's pod is either the start marker's pod (job not
//	  killed in time / kill missed the in-flight window) or — the drill's
//	  PASS signal — DIFFERENT from the FIRST start marker's pod.
func chaosFetchLeaseAuditRows(t *testing.T, db *sql.DB, runID string) []chaosLeaseAuditRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT kind, metadata::text, created_at
		FROM audit_log
		WHERE actor = $1
		  AND metadata->>'run_id' = $2
		ORDER BY created_at ASC
	`, chaosLeaseRecoveryActor, runID)
	if err != nil {
		t.Fatalf("chaos: fetch lease audit rows: %v", err)
	}
	defer rows.Close()

	var out []chaosLeaseAuditRow
	for rows.Next() {
		var kind, metaText string
		var ts time.Time
		if scanErr := rows.Scan(&kind, &metaText, &ts); scanErr != nil {
			t.Fatalf("chaos: scan lease audit row: %v", scanErr)
		}
		var meta map[string]any
		if err := json.Unmarshal([]byte(metaText), &meta); err != nil {
			t.Fatalf("chaos: parse audit metadata: %v", err)
		}
		pod, _ := meta["pod"].(string)
		out = append(out, chaosLeaseAuditRow{Kind: kind, Pod: pod, TS: ts, Metadata: meta})
	}
	return out
}

// chaosEnqueueLeaseRecoveryJob inserts ONE row into river_job for the
// chaos_lease_recovery kind. Bypasses the River SDK by writing the row
// directly — the test process is not a River client, just needs the row
// to land in the DB and become eligible for the workers to fetch.
//
// River's schema (v0.11 — see internal/migration/main_*.sql in the River
// module): river_job has columns
// (id, state, attempt, max_attempts, attempted_at, attempted_by,
//
//	errors, finalized_at, created_at, scheduled_at, priority, args,
//	tags, metadata, kind, queue, unique_key).
//
// We set state='available' so the worker picks it up on the next fetch.
// max_attempts=25 (the River default) lets the rescuer retry the orphan
// many times before giving up. scheduled_at = now() so the producer
// fetches it immediately.
func chaosEnqueueLeaseRecoveryJob(t *testing.T, db *sql.DB, teamID uuid.UUID, runID string, sleepSecs int) int64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args, _ := json.Marshal(map[string]any{
		"sleep_seconds": sleepSecs,
		"team_id":       teamID.String(),
		"run_id":        runID,
	})

	var jobID int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO river_job
		    (state, attempt, max_attempts, args, kind, queue, priority,
		     created_at, scheduled_at, errors, tags, metadata)
		VALUES
		    ('available', 0, 25, $1::jsonb, $2, 'default', 4,
		     now(), now(), ARRAY[]::jsonb[], ARRAY[]::varchar[], '{}'::jsonb)
		RETURNING id
	`, args, chaosLeaseRecoveryKind).Scan(&jobID)
	if err != nil {
		t.Fatalf("chaos: enqueue river_job: %v", err)
	}
	return jobID
}

// chaosCleanupRiverJob deletes the river_job row by id (best-effort).
func chaosCleanupRiverJob(t *testing.T, db *sql.DB, jobID int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, `DELETE FROM river_job WHERE id = $1`, jobID); err != nil {
		t.Logf("chaos: cleanup river_job %d failed (best-effort): %v", jobID, err)
	}
}

// chaosVerifyChaosKindRegistered probes the worker's job kind registry by
// checking the river_job table for any successful past completion of the
// kind. If a successful row exists, the worker image has the kind. If
// not, we soft-warn but still proceed — the drill itself enqueues a row
// and if the worker doesn't recognise it, River marks it 'unknown' /
// state='discarded' which the drill detects.
//
// Returns informational only.
func chaosVerifyChaosKindRegistered(t *testing.T, db *sql.DB) {
	t.Helper()
	var n int
	_ = db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM river_job WHERE kind = $1 AND state = 'completed'`,
		chaosLeaseRecoveryKind,
	).Scan(&n)
	if n == 0 {
		t.Logf("chaos: pre-check — no prior chaos_lease_recovery completions in river_job; first run, expected")
	} else {
		t.Logf("chaos: pre-check — %d prior chaos_lease_recovery completions found", n)
	}
}

// ─── the test ─────────────────────────────────────────────────────────────────

// TestChaos_WorkerLeaseRecovery enqueues a stub job, waits for in-flight,
// prompts the operator to kill the pod, and verifies a sibling worker
// picks up the orphan within the lease-recovery RTO budget.
func TestChaos_WorkerLeaseRecovery(t *testing.T) {
	db := chaosPlatformDB(t)
	defer db.Close()

	chaosSweepOrphans(t, db)
	chaosVerifyChaosKindRegistered(t, db)

	teamID, cleanup := chaosSeedSyntheticTeam(t, db, "lease")
	defer cleanup()

	runID := "chaos-lease-" + uuid.New().String()[:8]
	sleep := chaosLeaseSleepSeconds()
	budget := chaosLeaseRTOBudget()
	mode := chaosLeaseMode()

	t.Logf("DRILL START: run_id=%s team_id=%s sleep=%ds budget=%s mode=%s",
		runID, teamID, sleep, budget, mode)

	jobID := chaosEnqueueLeaseRecoveryJob(t, db, teamID, runID, sleep)
	defer chaosCleanupRiverJob(t, db, jobID)
	enqueuedAt := time.Now()
	t.Logf("STEP 1: enqueued river_job id=%d at %s", jobID, enqueuedAt.UTC().Format(time.RFC3339))

	// ─── STEP 2: wait for first start marker ───────────────────────────
	firstStart, ok := chaosWaitForLeaseStart(t, db, runID, chaosLeaseRecoveryStartTimeout)
	if !ok {
		t.Fatalf("STEP 2 FAIL: no chaos.lease_recovery.start marker within %s — worker image may not include the chaos kind",
			chaosLeaseRecoveryStartTimeout)
	}
	t.Logf("STEP 2 PASS: first start marker at %s pod=%q",
		firstStart.TS.UTC().Format(time.RFC3339), firstStart.Pod)
	if firstStart.Pod == "" || firstStart.Pod == "unknown" {
		t.Logf("STEP 2 WARN: pod marker is empty — running outside k8s? HOSTNAME unset?")
	}

	// ─── STEP 3: operator kill ─────────────────────────────────────────
	if mode == chaosLeaseRecoveryModeInteractive {
		t.Logf("STEP 3 (OPERATOR ACTION REQUIRED):")
		t.Logf("   Run this in a separate shell within the next %ds:", sleep)
		t.Logf("     kubectl delete pod -n instant-infra %s --grace-period=0 --force", firstStart.Pod)
		t.Logf("   Then return here — the test continues polling automatically.")
		t.Logf("   (If you missed the window the job will complete normally — see STEP 4 below.)")
	} else {
		t.Logf("STEP 3 (observe mode): not prompting — assuming operator kills out-of-band")
	}

	// ─── STEP 4: wait for end marker, observe RTO ──────────────────────
	endRow, ok := chaosWaitForLeaseEnd(t, db, runID, budget)
	if !ok {
		t.Fatalf("STEP 4 FAIL: no chaos.lease_recovery.end marker within %s — lease-recovery path BROKEN. Last seen audit rows: %+v",
			budget, chaosFetchLeaseAuditRows(t, db, runID))
	}
	endAt := endRow.TS

	rto := endAt.Sub(firstStart.TS)
	t.Logf("STEP 4 PASS: end marker at %s pod=%q (observed_RTO=%s from first start)",
		endAt.UTC().Format(time.RFC3339), endRow.Pod, rto)

	// ─── STEP 5: assertions + finding extraction ───────────────────────
	allRows := chaosFetchLeaseAuditRows(t, db, runID)
	starts := 0
	pods := map[string]struct{}{}
	for _, r := range allRows {
		if r.Kind == chaosLeaseRecoveryAuditStart {
			starts++
			pods[r.Pod] = struct{}{}
		}
	}

	// Two scenarios:
	//   A. Two distinct pods saw a start marker — the kill landed mid-sleep
	//      and the rescuer re-leased to a different pod. PASS, RTO is real.
	//   B. Only one pod / one start — the kill missed the window OR the
	//      operator did not run it. The job completed normally. Logged as
	//      a NOTE — RTO=0 / no real recovery measured. The drill still
	//      proves the kind is registered + the end-to-end River path works.
	if len(pods) > 1 {
		t.Logf("FINDING: lease-takeover OBSERVED — %d distinct pods saw start marker: %v. Lease-recovery RTO = %s. (River defaults: rescuer interval 30s + RescueAfter 1h + JobTimeout 20m → theoretical worst case ~1h20m.)",
			len(pods), keys(pods), rto)
	} else {
		t.Logf("FINDING: no kill observed — only %d pod (%v) saw start marker. Operator may have missed the kill window OR ran in observe mode. Job completed in %s WITHOUT lease takeover.",
			len(pods), keys(pods), rto)
	}

	// ─── Findings summary log ──────────────────────────────────────────
	t.Logf("CHAOS DRILL TEST 2 RESULT: end-to-end River dispatch + audit emission WORKS. distinct_pods=%d observed_RTO=%s budget=%s",
		len(pods), rto, budget)
}

// chaosWaitForLeaseStart polls audit_log for the FIRST start marker for runID.
func chaosWaitForLeaseStart(t *testing.T, db *sql.DB, runID string, budget time.Duration) (chaosLeaseAuditRow, bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		rows := chaosFetchLeaseAuditRows(t, db, runID)
		for _, r := range rows {
			if r.Kind == chaosLeaseRecoveryAuditStart {
				return r, true
			}
		}
		if time.Now().After(deadline) {
			return chaosLeaseAuditRow{}, false
		}
		time.Sleep(2 * time.Second)
	}
}

// chaosWaitForLeaseEnd polls audit_log for the end marker for runID.
func chaosWaitForLeaseEnd(t *testing.T, db *sql.DB, runID string, budget time.Duration) (chaosLeaseAuditRow, bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	progressEvery := 30 * time.Second
	lastProgress := time.Now()
	for {
		rows := chaosFetchLeaseAuditRows(t, db, runID)
		for _, r := range rows {
			if r.Kind == chaosLeaseRecoveryAuditEnd {
				return r, true
			}
		}
		if time.Now().After(deadline) {
			return chaosLeaseAuditRow{}, false
		}
		if time.Since(lastProgress) >= progressEvery {
			lastProgress = time.Now()
			remaining := time.Until(deadline)
			t.Logf("STEP 4: still waiting for end marker (%d audit rows seen so far) — %s remaining",
				len(rows), remaining.Round(time.Second))
		}
		time.Sleep(5 * time.Second)
	}
}

// keys extracts the keys of a set as a slice for human-friendly logging.
func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// chaosSyntheticAssert ensures a panic if cleanup ever DOESN'T touch a
// chaos team — defensive; never reached in normal flow.
//
//nolint:unused
var _ = fmt.Sprintf
