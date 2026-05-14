-- 045_deploy_ttl.sql — Deploy default 24h TTL (Wave FIX-J).
--
-- Motivation: agent-driven deploys silently linger forever today. We want the
-- default to be a 24h auto-expire so an experimental `/deploy/new` from a coding
-- agent doesn't accidentally hold a slot indefinitely. The agent (and the user
-- in front of it) gets six reminder emails over the final 12h, plus three
-- explicit "keep this" routes: a per-deploy POST /deployments/:id/make-permanent,
-- a custom TTL via POST /deployments/:id/ttl, and a team-wide
-- default_deployment_ttl_policy toggle via PATCH /api/v1/team/settings.
--
-- Safety: this migration is forward-only and idempotent. Existing rows are
-- NOT auto-expired by this change — see the explicit backfill UPDATE below
-- that sets ttl_policy='permanent' on every pre-existing deployment so the
-- 24h default never blows away anyone's running production deploy.
--
-- Columns:
--   expires_at         TIMESTAMPTZ — when the deployment auto-expires. NULL
--                                    means permanent (no TTL).
--   ttl_policy         TEXT       — 'auto_24h' | 'permanent' | 'custom'.
--                                    Distinguishes a deliberate user choice
--                                    ('permanent' / 'custom') from the
--                                    server-default ('auto_24h'). The
--                                    deployment_expirer worker only deletes
--                                    rows where ttl_policy != 'permanent' AND
--                                    expires_at < now().
--   reminders_sent     INT        — count of warning emails dispatched so far
--                                    (0..6). The reminder worker advances
--                                    one step per 2h tick. Used by the worker
--                                    to dedupe duplicate sends across ticks.
--   last_reminder_at   TIMESTAMPTZ — wall-clock of the most recent reminder
--                                    dispatched. Combined with reminders_sent
--                                    forms a CAS guard: a reminder fires only
--                                    when last_reminder_at IS NULL OR
--                                    last_reminder_at < now() - 2h AND
--                                    reminders_sent < 6.
--
-- Teams table addition:
--   default_deployment_ttl_policy — when 'permanent', POST /deploy/new defaults
--                                   to expires_at = NULL. When 'auto_24h',
--                                   POST /deploy/new defaults to expires_at =
--                                   now() + 24h. Per-deploy ttl_policy in the
--                                   request body overrides the team default.

ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ttl_policy TEXT NOT NULL DEFAULT 'auto_24h',
    ADD COLUMN IF NOT EXISTS reminders_sent INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_reminder_at TIMESTAMPTZ;

-- The CHECK constraint is added separately so the ADD COLUMN IF NOT EXISTS
-- above stays idempotent even when this migration is re-applied against a
-- partially-applied schema. We guard with a NOT EXISTS lookup so the second
-- apply doesn't error on a duplicate constraint name.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'deployments_ttl_policy_check'
    ) THEN
        ALTER TABLE deployments
            ADD CONSTRAINT deployments_ttl_policy_check
            CHECK (ttl_policy IN ('auto_24h', 'permanent', 'custom'));
    END IF;
END
$$;

-- Partial index: only pending TTL rows. The reminder + expirer workers scan
-- this index to find candidate rows; deleted / expired rows don't need to
-- be re-evaluated, so excluding them keeps the index narrow.
CREATE INDEX IF NOT EXISTS idx_deployments_expires_pending
    ON deployments (expires_at)
    WHERE expires_at IS NOT NULL AND status NOT IN ('deleted', 'expired');

-- ── Teams: per-team default policy ───────────────────────────────────────────
ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS default_deployment_ttl_policy TEXT NOT NULL DEFAULT 'auto_24h';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'teams_default_deployment_ttl_policy_check'
    ) THEN
        ALTER TABLE teams
            ADD CONSTRAINT teams_default_deployment_ttl_policy_check
            CHECK (default_deployment_ttl_policy IN ('auto_24h', 'permanent'));
    END IF;
END
$$;

-- ── Backfill: don't blow up existing deploys ─────────────────────────────────
--
-- Every row that existed BEFORE this migration ran is grandfathered into
-- ttl_policy='permanent'. The default at the column level is 'auto_24h' for
-- NEW rows going forward, but a running production deploy must not silently
-- enter a 24h countdown the moment this migration ships.
--
-- We branch on (expires_at IS NULL) so anonymous-tier rows that already have
-- a TTL (set elsewhere) keep auto_24h. WHERE clause is idempotent.
UPDATE deployments
SET    ttl_policy = 'permanent'
WHERE  expires_at IS NULL
  AND  ttl_policy = 'auto_24h';
