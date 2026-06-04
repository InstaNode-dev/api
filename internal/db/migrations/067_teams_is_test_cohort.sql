-- Migration: 067_teams_is_test_cohort
--
-- Add teams.is_test_cohort — the cohort-isolation foundation (W0 / PR-1) for the
-- continuous synthetic-monitoring program. See
-- docs/sessions/2026-06-04/TEST-ACCOUNTS-AND-NR-SYNTHETICS-PLAN.md §1.5/§1.6.
--
-- Background:
--   The synthetic-monitoring program seeds durable per-tier test teams
--   (`synthetic+hobby@instanode.dev`, etc.) and provisions real resources on a
--   continuous cadence. Without an isolation flag those seeded teams would look
--   like real customers to every background job and funnel/billing surface:
--     - quota nudges + expiry/TTL warning emails would fire at synthetic
--       addresses (Brevo-rejected noise + ledger pollution),
--     - the billing reconciler would flag them as drift (no real Razorpay sub),
--     - the conversion funnel / churn predictor would count synthetic activity
--       in the real 2%/20% targets,
--     - self-serve checkout / change-plan would attempt a real charge.
--
--   `is_test_cohort` is the single tag every such path keys off to no-op or
--   exclude the team. It is INERT by default: every existing team gets `false`,
--   so behaviour is unchanged for all real teams until a seeder sets it true.
--
-- This migration:
--   - Adds teams.is_test_cohort BOOLEAN NOT NULL DEFAULT false.
--   - Adds a tiny PARTIAL index on the true rows only. The team-iterating jobs
--     (worker-side, follow-up PR) filter `AND NOT is_test_cohort`; the api-side
--     charge guards (this PR) look up a single team by id. The partial index
--     covers the "list the synthetic teams" / "is this team synthetic" lookups
--     while staying near-zero cost (only the handful of seeded rows are
--     indexed — the DEFAULT-false universe is excluded).
--
-- Idempotent: ADD COLUMN IF NOT EXISTS + CREATE INDEX IF NOT EXISTS, safe to
-- re-run on every startup (matches the RunMigrations forward-only contract).
--
-- Rollback (forward-only project; documented, not auto-applied):
--   DROP INDEX IF EXISTS idx_teams_is_test_cohort;
--   ALTER TABLE teams DROP COLUMN IF EXISTS is_test_cohort;
--   (Safe — no FK or other constraint references this column.)

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS is_test_cohort BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_teams_is_test_cohort
    ON teams (id)
    WHERE is_test_cohort;
