-- Migration: 057_resources_pending_status
--
-- Add 'pending' as a permitted value in the resources.status CHECK constraint.
--
-- Background (MR-P0-2 — BugBash 2026-05-20):
--   The crash-recovery subsystem is dead code. `provisioner_reconciler` sweeps
--   `WHERE status='pending'`, the `idx_resources_pending_sweep` partial index
--   (migration 030) filters on it, and migration 030's `last_reconciled_at`
--   column exists to support it — but NOTHING ever wrote `status='pending'`.
--   CreateResource inserted every row at the column DEFAULT 'active' BEFORE the
--   backend provision RPC ran, so an api crash mid-provision stranded an
--   'active' row with connection_url=NULL that the reconciler could never see.
--
--   models.CreateResource now inserts 'pending' and a new MarkResourceActive
--   flips the row to 'active' ONLY after the backend RPC + connection-URL +
--   provider-resource-id persistence all succeed. That makes the reconciler's
--   sweep, the partial index, and last_reconciled_at all live.
--
--   But migration 049's CHECK constraint is:
--     CHECK (status IN ('active', 'paused', 'suspended', 'expired', 'deleted', 'reaped'))
--   — 'pending' is absent. Without this migration every CreateResource INSERT
--   would hit constraint-violation 23514 and provisioning would be a total
--   outage.
--
-- Fix:
--   DROP the existing CHECK constraint (IF EXISTS — safe on a fresh schema and
--   on prod where it exists) and re-add it with 'pending' included. Idempotent:
--   the re-added CHECK uses the same syntax, so re-running on a schema that
--   already applied this migration is harmless.
--
-- Status semantics (updated):
--   pending    — row inserted, backend provision RPC + URL persistence not yet
--                complete; the transient mid-provision state. NOT usable.
--                The provisioner_reconciler crash-recovery sweep keys on this.
--   active     — provisioned, accepting connections (or status-only for queue/storage/webhook)
--   paused     — user-initiated pause (Pro+ only); infra revoked; data preserved
--   suspended  — system-initiated suspend on storage quota breach; infra revoked
--   expired    — TTL reached (anonymous resources); soft-deleted equivalent for anon
--   deleted    — user-deleted (permanent credentials removed)
--   reaped     — legacy: worker-reaped before 'deleted' was the canonical term

ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_status_check;
ALTER TABLE resources
    ADD CONSTRAINT resources_status_check
    -- Forward-consistent full status set (incident 2026-06-10): include 'failed'
    -- (added in 070) so re-applying 057 on boot can't crash on a valid failed
    -- row before 070 runs. 024/049/057/070 now all define the same canonical set.
    CHECK (status IN ('pending', 'active', 'paused', 'suspended', 'failed', 'expired', 'deleted', 'reaped'));

-- idx_resources_pending_sweep (the partial index the reconciler scans) was
-- already created by migration 030_resource_heartbeat.sql — it indexes
-- WHERE status='pending' and has been matching zero rows since. No new index
-- is needed here; this migration only widens the CHECK constraint so rows can
-- actually carry the 'pending' value the index was built for.
