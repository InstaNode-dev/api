-- 069_pending_checkouts_cascade — make pending_checkouts.team_id cascade on team delete.
--
-- WHY THIS EXISTS
-- ---------------
-- 053_pending_checkouts created the FK as `team_id UUID NOT NULL REFERENCES
-- teams(id)` with NO `ON DELETE CASCADE` — the ONLY team-child table that omits
-- it (every other child: deployments, stacks, api_keys, audit_log, vault,
-- custom_domains, pending_deletions, pending_propagations, … all CASCADE).
--
-- DeleteTeamHard (the e2e-account reap) and the worker team_deletion_executor
-- both delete a team with a single `DELETE FROM teams`, relying on the children
-- to cascade. A team that ever started a checkout has a pending_checkouts row,
-- so the delete fails:
--   pq: update or delete on table "teams" violates foreign key constraint
--   "pending_checkouts_team_id_fkey" on table "pending_checkouts"
-- This surfaced the moment test-cohort checkout was armed (a cohort upgrade
-- creates a pending_checkouts row) — the reap 503'd and the cohort team leaked,
-- breaking the rule-24 "cohort data is always reaped" guarantee.
--
-- Fix: align the FK with every other team-child table — ON DELETE CASCADE. A
-- resolved or unresolved pending_checkouts row is per-team bookkeeping; when the
-- team is gone the row is meaningless, so cascading the delete is correct.
-- Idempotent (DROP IF EXISTS + re-ADD) so it is safe to re-run.

ALTER TABLE pending_checkouts DROP CONSTRAINT IF EXISTS pending_checkouts_team_id_fkey;
ALTER TABLE pending_checkouts
  ADD CONSTRAINT pending_checkouts_team_id_fkey
  FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE;
