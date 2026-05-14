-- Migration: 032_team_deletion — GDPR Article 17 right-to-be-forgotten state
-- machine. Adds team-level deletion lifecycle columns + index so the API's
-- DELETE /api/v1/team / POST /api/v1/team/restore endpoints and the worker's
-- nightly team_deletion_executor job have a stable schema to drive.
--
-- The flow:
--   1. Owner POSTs DELETE /api/v1/team with {"confirm_team_slug":"<slug>"}.
--      API flips teams.status='deletion_requested' + deletion_requested_at=now(),
--      pauses every team resource (status='paused'), best-effort cancels the
--      Razorpay subscription, and emits team.deletion_requested.
--   2. Within 30 days the owner can POST /api/v1/team/restore to halt the
--      deletion — status returns to 'active', paused resources resume.
--      After 30 days the restore endpoint rejects.
--   3. The worker's team_deletion_executor runs daily 03:00 UTC, sweeps
--      deletion_requested rows older than 30d, hard-deletes S3 backups, calls
--      provisioner DeprovisionResource per active row, NULLs PII on team +
--      user rows, NULLs connection_url + metadata + key_prefix on resource
--      rows, then flips teams.status='tombstoned' + tombstoned_at=now().
--
-- Why default 'active' + CHECK: every existing row pre-migration is treated
-- as a normal active team — no backfill needed. The CHECK constraint stops
-- callers from writing an unrecognised status value (the application code
-- and the worker are the only writers; this is a defensive guardrail, not a
-- substitute for code review).
--
-- Why a partial index on deletion_requested_at WHERE status='deletion_requested':
-- the worker's nightly sweep is the only query against deletion_requested_at,
-- and it always filters on status. A full index would mostly index NULLs and
-- pay nothing back. The partial index is small (one entry per pending team)
-- and the query plan is a single index scan with no filter step.
--
-- Why nullable tombstoned_at: every tombstoned row also has
-- status='tombstoned' so the value can be inferred for a CHECK, but we keep
-- it nullable so the audit trail (which row was tombstoned when) is explicit
-- in one column rather than a join against audit_log.

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active','deletion_requested','tombstoned'));

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ;

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS tombstoned_at TIMESTAMPTZ;

-- Partial index — only the (small) set of pending-deletion teams is indexed.
-- The worker scans by deletion_requested_at + 30d < now() and the partial
-- predicate keeps the index footprint bounded to the active dunning queue.
CREATE INDEX IF NOT EXISTS idx_teams_pending_deletion
    ON teams(deletion_requested_at) WHERE status = 'deletion_requested';
