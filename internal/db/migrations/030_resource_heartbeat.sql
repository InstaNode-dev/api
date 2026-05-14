-- 030_resource_heartbeat.sql — companion migration for the worker's
-- provisioner_reconciler and resource_heartbeat jobs (shipped 2026-05-13).
--
-- The worker repo does not own a migration runner. This file is the
-- canonical source the api repo will copy into
-- api/internal/db/migrations/030_resource_heartbeat.sql in a follow-up PR.
-- Keep the two in sync; the worker tests assume these columns exist.
--
-- Columns:
--   * last_seen_at        — set by resource_heartbeat on a successful probe.
--                           NULL means "never probed yet" (newly-provisioned).
--   * degraded            — heartbeat-set flag; the dashboard reads this to
--                           surface "your Postgres is unreachable" banners.
--                           NOT NULL with default false so existing rows
--                           don't need a backfill.
--   * degraded_reason     — last probe error string. Cleared when degraded
--                           transitions false. Capped to TEXT (no length
--                           limit) but heartbeat truncates to 500 chars.
--   * last_reconciled_at  — provisioner_reconciler stamp. Prevents tight-
--                           loop re-sweeping of the same pending row across
--                           consecutive 2-minute ticks.
--
-- Indexes:
--   * idx_resources_degraded — partial; dashboard "show me my broken
--                              resources" queries hit this with WHERE degraded.
--   * idx_resources_pending_sweep — partial; reconciler sweep query filters
--                                    by status='pending' AND created_at; the
--                                    partial index keeps the scan tiny even
--                                    when the active resource count is huge.

ALTER TABLE resources ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS degraded BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS degraded_reason TEXT;
ALTER TABLE resources ADD COLUMN IF NOT EXISTS last_reconciled_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_resources_degraded
    ON resources(degraded)
    WHERE degraded;

CREATE INDEX IF NOT EXISTS idx_resources_pending_sweep
    ON resources(status, created_at)
    WHERE status = 'pending';
