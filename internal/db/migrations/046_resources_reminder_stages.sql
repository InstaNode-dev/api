-- 046_resources_reminder_stages.sql
--
-- Replace the single-stamp anon-expiry reminder (015) with a multi-stage
-- counter so a free-tier resource can receive up to 3 reminders at the
-- 12h, 6h, and 1h marks before expires_at. Mirrors the pattern shipped
-- in 045_deploy_ttl.sql for deployments.
--
-- Columns:
--   reminders_sent     INT NOT NULL DEFAULT 0
--                      Monotonic counter, 0..3. Stage N fires only when
--                      reminders_sent < N. Advanced via CAS in the worker
--                      so two concurrent sweeps cannot double-fire a stage.
--
--   last_reminder_at   TIMESTAMPTZ NULL
--                      Wall-clock of the most recent reminder dispatch.
--                      Provides a cooldown floor in case the stage windows
--                      ever overlap (e.g. if a TTL is bumped).
--
-- expiry_reminded_at is intentionally kept. Existing rows with that column
-- set will have reminders_sent backfilled to 1 so we don't re-send a stale
-- "12h" reminder on a row that already received its single legacy reminder.

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS reminders_sent   INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_reminder_at TIMESTAMPTZ;

-- Backfill: rows that received the legacy single reminder are treated as
-- having sent the first stage (12h). They will still be eligible for the
-- 6h and 1h stages if they're still inside those windows when this ships.
UPDATE resources
   SET reminders_sent = 1,
       last_reminder_at = COALESCE(last_reminder_at, expiry_reminded_at)
 WHERE expiry_reminded_at IS NOT NULL
   AND reminders_sent = 0;

-- Index supports the per-sweep candidate query (tier='free' AND status='active'
-- AND expires_at within window AND reminders_sent < 3).
CREATE INDEX IF NOT EXISTS resources_anon_expiry_sweep_idx
    ON resources (expires_at)
 WHERE tier = 'free' AND status = 'active' AND reminders_sent < 3;
