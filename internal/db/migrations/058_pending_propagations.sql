-- Migration: 058_pending_propagations
--
-- An explicit, durable "propagation queue" for events whose user-visible state
-- has already been committed in the platform DB (teams.plan_tier flipped,
-- resources.tier elevated via the atomic upgrade tx) but whose corresponding
-- infrastructure-side regrade (provisioner RegradeResource → ALTER ROLE …
-- CONNECTION LIMIT, CONFIG SET maxmemory, etc.) is still pending.
--
-- Background — the gap this closes
-- --------------------------------
-- Today the api's `handleSubscriptionCharged` (billing.go) calls
-- `UpgradeTeamAllTiersWithSubscription`. That atomic tx flips `teams.plan_tier`
-- + `resources.tier` and is the user-visible "you are now on Pro" signal. The
-- ACTUAL backend regrade (provisioner RegradeResource RPC → infra cap change)
-- is left to the worker's `entitlement_reconciler` polling every ~5 min.
--
-- If that reconciler fails repeatedly — provisioner outage, a one-off bad pod,
-- a Razorpay webhook re-fire racing pod restart — the customer is left with a
-- "Pro tier on paper" but "hobby-grade infra" (the snapshot's connection cap
-- never landed on the live ALTER ROLE …). The drift would correct itself on
-- the next successful sweep, but nothing alerts when consecutive sweeps fail
-- for the SAME team — the reconciler just logs WARNs.
--
-- `pending_propagations` is the durable backstop. The api enqueues a row at
-- charge-confirm time. The worker's new `propagation_runner` job pulls rows
-- whose `next_attempt_at <= now()` and dispatches them by `kind` — for
-- `tier_elevation` that means calling RegradeResource for every active
-- resource on the team. Success stamps `applied_at`. Per-resource failures
-- bump `attempts`, persist `last_error`, and reschedule via exponential
-- backoff. After `maxAttempts` (10) the row is dead-lettered (`failed_at`)
-- and emits a `propagation.dead_lettered` audit row at CRITICAL severity —
-- the alert-able signal an operator can key on.
--
-- This is intentionally a SEPARATE table from `audit_log`: the audit log is
-- append-only, so it cannot carry mutable `attempts` / `next_attempt_at` /
-- `applied_at` state. It is also separate from the River queue (which the
-- worker uses for its own periodic ticks) — River is the worker's internal
-- scheduler and does not gate on platform DB rows; we want this gate ON the
-- platform DB so the api writes it transactionally next to the upgrade.
--
-- Schema notes
-- ------------
--   id              — surrogate PK. The (kind, team_id, target_tier) tuple is
--                     NOT unique: a customer who upgrades hobby → pro and
--                     later pro → growth must enqueue two distinct rows
--                     (each carrying its own target_tier snapshot). The
--                     idempotency contract is per-row, not per-team.
--
--   kind            — propagation kind discriminator. Today the only kind
--                     is 'tier_elevation', but the column is open so future
--                     kinds (vault re-encryption, custom-domain DNS,
--                     deploy ingress patch …) can use the same machinery
--                     without a fresh migration. A future kind must register
--                     a handler in the worker's `propagation_runner` registry
--                     — see CLAUDE.md rule 18 (registry-iterating tests).
--
--   target_tier     — NULL for non-tier kinds; for 'tier_elevation' the
--                     tier the api wants the worker to regrade resources
--                     TO. This is a SNAPSHOT at enqueue time — matches the
--                     "resource.tier is the entitlement-of-record"
--                     invariant (CLAUDE.md convention 5).
--
--   payload         — open JSONB blob for kind-specific extra data. Empty
--                     for tier_elevation today.
--
--   attempts        — incremented per failed dispatch. Capped at maxAttempts
--                     in the worker (10) — exceeding it transitions the row
--                     to failed_at (dead-lettered).
--
--   last_attempt_at — wall-clock of the most recent dispatch (success or
--                     failure). Lets an operator see when the worker last
--                     touched this row.
--
--   last_error      — truncated error string from the most recent failure.
--                     NULL on a fresh row and after every successful
--                     attempt (we clear it on success so the row's final
--                     state is clean).
--
--   next_attempt_at — the earliest wall-clock the worker may pick this row
--                     up again. Defaults to now() so a fresh row is
--                     immediately eligible. After a failure the worker sets
--                     this to now() + exp_backoff(attempts).
--
--   applied_at      — terminal: the propagation succeeded. The row is left
--                     in place (not deleted) as the success ledger; the
--                     worker's predicate filters on `applied_at IS NULL`.
--
--   failed_at       — terminal: the propagation dead-lettered after
--                     maxAttempts. Mutually exclusive with applied_at;
--                     paired with a propagation.dead_lettered audit row
--                     and a structured ERROR log line so the NR alert
--                     can key on either signal.
--
--   created_at      — wall-clock at INSERT. Useful for SLA reports
--                     ("p95 time-to-applied for tier_elevation rows
--                     this week").
--
-- Index strategy
-- --------------
-- The hot query is the worker's per-tick pick:
--
--   SELECT ... FROM pending_propagations
--    WHERE applied_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
--    ORDER BY next_attempt_at
--    FOR UPDATE SKIP LOCKED LIMIT 50
--
-- The partial index `(next_attempt_at) WHERE applied_at IS NULL AND failed_at
-- IS NULL` covers the entire predicate — only "active" rows (no terminal
-- timestamp) live in the index, which keeps it small as the success+failure
-- ledger grows. SKIP LOCKED guarantees a replicas-N cluster never double-
-- processes a row.

CREATE TABLE IF NOT EXISTS pending_propagations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind            TEXT NOT NULL,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    target_tier     TEXT,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempts        INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at      TIMESTAMPTZ,
    failed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Hot path: the worker's per-tick "what's eligible now" sweep.
-- Partial index: only active (non-terminal) rows live here.
CREATE INDEX IF NOT EXISTS idx_pending_propagations_due
    ON pending_propagations (next_attempt_at)
    WHERE applied_at IS NULL AND failed_at IS NULL;

-- Operator queries: "show me every dead-lettered row for triage". Small,
-- bounded set; the index makes the failed_at filter cheap.
CREATE INDEX IF NOT EXISTS idx_pending_propagations_failed
    ON pending_propagations (failed_at)
    WHERE failed_at IS NOT NULL;

-- Per-team lookups: "did the propagation for team X land?". Used by tests
-- and by future operator tooling. ON DELETE CASCADE on the FK already
-- guarantees team-tombstone cleanup; the index just makes the lookup fast.
CREATE INDEX IF NOT EXISTS idx_pending_propagations_team
    ON pending_propagations (team_id, kind);
