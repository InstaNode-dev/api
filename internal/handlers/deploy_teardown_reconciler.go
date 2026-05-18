package handlers

// deploy_teardown_reconciler.go — P3 fix: tear down expired deployments.
//
// PROBLEM SHAPE
//
// The worker's DeploymentExpirer sweeps deployments past their 24h TTL and
// flips status='expired'. Its source comment claimed "the api reconciler
// tears down" the compute — but no such api reconciler existed. The
// worker's deploy_status_reconcile.go only polls building|deploying|healthy
// rows and never calls Teardown. Result: every auto-expired deployment left
// a live k8s namespace / pod / Ingress / cert running and billed forever —
// the free-tier 24h TTL was a lie at the infra layer.
//
// FIX
//
// This file adds a background sweep INSIDE the api (the only service that
// holds a compute.Provider — the worker module is deliberately decoupled
// from the k8s SDK). Every deployTeardownInterval it:
//
//   1. Lists deployments in status='expired' with a non-empty provider_id
//      (GetExpiredDeploymentsAwaitingTeardown).
//   2. Calls compute.Teardown(provider_id) — the SAME path DELETE /deploy/:id
//      uses (deploy.go doImmediateDelete) — to destroy the namespace / pod /
//      Ingress / cert.
//   3. On a successful (or already-gone) teardown, flips the row to the
//      terminal 'deleted' status via MarkDeploymentTornDown so it is never
//      reprocessed and stops being counted as a tier slot.
//
// Idempotency / no double-teardown: MarkDeploymentTornDown's guarded
// `WHERE status = 'expired'` means a row a DELETE /deploy/:id already
// cleaned (status advanced past 'expired') is left alone — and the next
// sweep's SELECT no longer returns a 'deleted' row, so a row is torn down
// at most once. compute.Teardown itself is safe on an already-deleted
// namespace (k8s NotFound is treated as success by the provider).
//
// STACKS
//
// Expired STACKS do NOT need a counterpart here. Unlike deployments (which
// the worker leaves in a non-terminal 'expired' status), the worker's
// ExpireStacksWorker already DELETEs the k8s namespace AND removes the
// stacks row in one pass — there is no leaked-infra "expired" stack state
// for an api reconciler to pick up. See worker/internal/jobs/expire_stacks.go.

import (
	"context"
	"log/slog"
	"time"

	"instant.dev/internal/metrics"
	"instant.dev/internal/models"
	"instant.dev/internal/safego"
)

// deployTeardownInterval is how often the api sweeps for expired-but-not-
// torn-down deployments. 60s matches the worker's DeploymentExpirer cadence
// so a row spends at most ~1 expirer tick + ~1 teardown tick (~2 min) with
// live-but-unpaid infra before its compute is destroyed.
const deployTeardownInterval = 60 * time.Second

// deployTeardownBatchLimit caps how many expired deployments one sweep
// processes. A generous bound — even a large expiry backlog drains within a
// few ticks without one sweep monopolising a k8s-API connection.
const deployTeardownBatchLimit = 100

// StartTeardownReconciler launches the background teardown sweep in its own
// goroutine and returns immediately. Cancel ctx (e.g. on server shutdown)
// to stop the loop. Router.New wires this once at construction time.
//
// The reconciler is a no-op-safe singleton: if the api is misconfigured
// onto the noop compute provider, Teardown returns nil and rows still
// advance to 'deleted' — the sweep degrades gracefully rather than
// blocking startup.
func (h *DeployHandler) StartTeardownReconciler(ctx context.Context) {
	safego.Go("deploy.teardown_reconciler", func() {
		// Recover so a panic in one sweep can never crash the api pod —
		// fire-and-forget background goroutines must be panic-isolated
		// (reliability rule: no unguarded fire-and-forget goroutines).
		defer func() {
			if r := recover(); r != nil {
				slog.Error("deploy.teardown_reconciler.panic", "panic", r)
			}
		}()

		ticker := time.NewTicker(deployTeardownInterval)
		defer ticker.Stop()

		slog.Info("deploy.teardown_reconciler.started",
			"interval", deployTeardownInterval.String())

		for {
			select {
			case <-ctx.Done():
				slog.Info("deploy.teardown_reconciler.stopped")
				return
			case <-ticker.C:
				h.RunTeardownSweep(ctx)
			}
		}
	})
}

// RunTeardownSweep executes one teardown pass. Errors on individual rows are
// logged and swallowed so one bad deployment never stalls the rest — same
// fail-open posture as the worker's reconcilers.
//
// P1-W5-17 (bug-hunt 2026-05-18): the api runs replicas:2 and this sweep
// fires in every pod. The whole sweep now runs inside ONE transaction whose
// SELECT carries FOR UPDATE SKIP LOCKED — each expired deployment is row-locked
// by the pod that selects it, so the sibling pod's concurrent sweep skips
// every claimed row and never double-invokes compute.Teardown on the same
// namespace. The lock is held until Commit; SKIP LOCKED means the loser pod
// no-ops rather than blocking.
func (h *DeployHandler) RunTeardownSweep(ctx context.Context) {
	start := time.Now()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		slog.Error("deploy.teardown_reconciler.begin_tx_failed", "error", err)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	expired, err := models.GetExpiredDeploymentsAwaitingTeardown(ctx, tx, deployTeardownBatchLimit)
	if err != nil {
		slog.Error("deploy.teardown_reconciler.list_failed", "error", err)
		return
	}
	if len(expired) == 0 {
		// Nothing claimed — commit the empty tx to release it promptly.
		if commitErr := tx.Commit(); commitErr != nil {
			slog.Error("deploy.teardown_reconciler.commit_failed", "error", commitErr)
			return
		}
		committed = true
		return
	}

	var tornDown, failed int
	for _, d := range expired {
		// Teardown the compute — the SAME provider call DELETE /deploy/:id
		// makes. k8s NotFound (namespace already gone) is success at the
		// provider layer, so a partially-cleaned deploy still advances.
		if teardownErr := h.compute.Teardown(ctx, d.ProviderID); teardownErr != nil {
			slog.Warn("deploy.teardown_reconciler.teardown_failed",
				"deploy_id", d.ID, "app_id", d.AppID,
				"provider_id", d.ProviderID, "error", teardownErr)
			// Leave the row at 'expired' — the next sweep retries the
			// teardown. We do NOT mark it 'deleted' on a failed teardown,
			// otherwise the infra would leak silently with no retry.
			failed++
			continue
		}

		n, markErr := models.MarkDeploymentTornDown(ctx, tx, d.ID)
		if markErr != nil {
			slog.Error("deploy.teardown_reconciler.mark_failed",
				"deploy_id", d.ID, "app_id", d.AppID, "error", markErr)
			// The compute is already gone but the row is still 'expired',
			// so the next sweep re-selects it and retries forever. Surface
			// that on a counter so a stuck row is alertable in NR instead
			// of being a silent log line.
			metrics.DeployTeardownMarkFailed.Inc()
			failed++
			continue
		}
		if n == 0 {
			// Row advanced past 'expired' between the SELECT and the
			// UPDATE (e.g. a concurrent DELETE /deploy/:id). Compute is
			// torn down either way — not a fault.
			continue
		}

		slog.Info("deploy.teardown_reconciler.torn_down",
			"deploy_id", d.ID, "app_id", d.AppID,
			"provider_id", d.ProviderID, "team_id", d.TeamID)
		tornDown++
	}

	// Commit releases the FOR UPDATE SKIP LOCKED row locks and persists the
	// status flips. A commit failure rolls the whole sweep back: the torn-down
	// compute is already gone but the rows stay 'expired', so the next sweep
	// re-selects and re-marks them (MarkDeploymentTornDown is idempotent and
	// compute.Teardown is NotFound-safe — no double-teardown harm).
	if commitErr := tx.Commit(); commitErr != nil {
		slog.Error("deploy.teardown_reconciler.commit_failed",
			"error", commitErr, "torn_down", tornDown, "failed", failed)
		return
	}
	committed = true

	slog.Info("deploy.teardown_reconciler.sweep_completed",
		"candidates", len(expired),
		"torn_down", tornDown,
		"failed", failed,
		"duration_ms", time.Since(start).Milliseconds())
}
