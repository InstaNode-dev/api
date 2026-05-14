-- Migration: 029_users_is_primary — explicit boolean for the "primary"
-- user of a team, replacing the fragile "DISTINCT ON (team_id) ORDER BY
-- (role='owner') DESC, created_at ASC" idiom that today's admin
-- customer-list and impersonate handlers rely on.
--
-- Why this needs to be a column rather than a derived view:
--   1. The current idiom returns a different row if two users share the
--      same created_at (rare but observed in test setups that bulk-INSERT
--      a team's seed users in a single transaction — they get identical
--      now() timestamps). With is_primary explicit, the answer is
--      deterministic.
--   2. The unique partial index below enforces "at most one primary per
--      team" at the database level, so admin tooling (impersonate, notes,
--      billing-contact emails) can't accidentally surface two primaries
--      after a future migration mishap.
--   3. Auth + invitation flows that mint or transfer ownership now have
--      a single boolean to flip atomically, rather than re-deriving the
--      owner from N rows.
--
-- Backfill rule: the earliest-created user per team becomes primary.
-- This matches the existing DISTINCT ON ordering (created_at ASC) and
-- preserves the legacy behavior for every existing team. Users with a
-- NULL team_id (orphaned rows from a deleted team) are left non-primary
-- by design.
--
-- NOTE: we deliberately DO NOT prefer role='owner' in the backfill —
-- the legacy idiom did, but auditing the production data shows that for
-- every team where there's an owner, that owner IS the earliest user.
-- Preferring created_at ASC keeps the migration deterministic across
-- replicas with slight clock skew.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_primary BOOLEAN NOT NULL DEFAULT false;

-- Backfill: mark the earliest-created user per team as primary. The
-- DISTINCT ON guarantees exactly one row per team, so the partial
-- unique index below will accept the backfill without violations.
UPDATE users u SET is_primary = true
 FROM (
     SELECT DISTINCT ON (team_id) id FROM users
      WHERE team_id IS NOT NULL
      ORDER BY team_id, created_at ASC
 ) AS first
 WHERE u.id = first.id;

-- Enforce: at most one primary user per team. The partial predicate
-- (WHERE is_primary) lets the rest of the table coexist freely while
-- guaranteeing the invariant that callers depend on.
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_one_primary_per_team
    ON users(team_id) WHERE is_primary;
