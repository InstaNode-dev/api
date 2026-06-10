-- Migration: 049_resources_suspended_status
--
-- Add 'suspended' as a permitted value in the resources.status CHECK constraint.
--
-- Background (P0-3 / P0-4 — 2026-05-16):
--   worker/internal/jobs/quota.go writes `status = 'suspended'` when a resource
--   exceeds its plan's storage quota. However, migration 024_resources_paused_status.sql
--   defines the CHECK constraint as:
--     CHECK (status IN ('active', 'paused', 'expired', 'deleted', 'reaped'))
--   — 'suspended' is absent. Every UPDATE hits constraint-violation 23514, is
--   logged as "suspend_failed", and the resource stays 'active'. Storage quota
--   enforcement is therefore a complete silent no-op.
--
-- Fix:
--   DROP the existing CHECK constraint (IF EXISTS — safe on a fresh schema that
--   has never applied the constraint, and safe on prod where it exists) and
--   re-add it with 'suspended' included. Idempotent: the re-added CHECK uses
--   the same syntax so re-running on a schema that already applied this
--   migration is harmless.
--
-- Status semantics (updated):
--   active     — provisioned, accepting connections (or status-only for queue/storage/webhook)
--   paused     — user-initiated pause (Pro+ only); infra revoked; data preserved
--   suspended  — system-initiated suspend on storage quota breach; infra revoked;
--                auto-unsuspend when usage drops below limit on next EnforceStorageQuota run
--   expired    — TTL reached (anonymous resources); soft-deleted equivalent for anon
--   deleted    — user-deleted (permanent credentials removed)
--   reaped     — legacy: worker-reaped before 'deleted' was the canonical term

ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_status_check;
ALTER TABLE resources
    ADD CONSTRAINT resources_status_check
    -- Forward-consistent full status set (incident 2026-06-10): include 'pending'
    -- (added in 057) so re-applying 049 on boot can't crash on a valid pending
    -- row before 057 runs. 024/049/057 now all define the same canonical set.
    CHECK (status IN ('pending', 'active', 'paused', 'suspended', 'expired', 'deleted', 'reaped'));

-- Partial index for the auto-unsuspend scan.
-- EnforceStorageQuotaWorker scans WHERE status = 'suspended' on every run to
-- re-check usage and flip back to 'active' when the customer is back under limit.
-- A partial index keeps this scan O(suspended-rows) not O(all-resources).
CREATE INDEX IF NOT EXISTS idx_resources_suspended
    ON resources (created_at)
    WHERE status = 'suspended';
