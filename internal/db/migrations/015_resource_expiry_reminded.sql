-- Migration: 015_resource_expiry_reminded
-- Adds a timestamp column used by the worker's ExpiryReminderJob to dedupe
-- pre-expiry reminder emails so we send at most one per resource.
--
-- The column is NULL until the worker successfully sends (or attempts) a
-- reminder for the row, after which it is set to now(). The hourly job query
-- (worker/internal/jobs/expiry_reminder.go) filters on
-- `expiry_reminded_at IS NULL` so a second pass over the same row is a no-op.
--
-- We do NOT clear this column on tier upgrades / TTL extension — once a user
-- has been emailed about a specific resource we don't email them again for
-- the same row. If the resource is permanently saved by a paid plan it will
-- never satisfy the window predicate anyway.

ALTER TABLE resources ADD COLUMN IF NOT EXISTS expiry_reminded_at TIMESTAMPTZ;

-- Partial index keeps the dedupe scan cheap: only rows that are still
-- eligible to be reminded (claimed-but-unpaid, expiring soon, not yet
-- reminded) live in the index.
CREATE INDEX IF NOT EXISTS idx_resources_expiry_reminder
    ON resources(expires_at)
    WHERE expiry_reminded_at IS NULL
      AND team_id IS NOT NULL
      AND tier = 'free'
      AND status = 'active'
      AND expires_at IS NOT NULL;
