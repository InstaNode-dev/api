-- 016_stack_env.sql — Real env promotion as a Pro-tier feature (§10.17).
-- (Renumbered from 015 to resolve a collision with 015_resource_expiry_reminded.sql
--  which landed concurrently for the expiry-reminder worker job.)
--
-- Today the stacks table has no concept of which environment (production,
-- staging, dev) a deploy belongs to. Vault is genuinely env-scoped, but
-- stacks are not — meaning "promote staging → production" cannot exist
-- because the two stacks aren't even linkable.
--
-- This migration introduces:
--   1. stacks.env            — TEXT NOT NULL DEFAULT 'production'. Every
--                              existing stack is treated as production. New
--                              stacks default to production unless the
--                              promote endpoint or a future env-aware deploy
--                              path sets otherwise.
--   2. stacks.parent_stack_id — UUID nullable, self-FK. When the promote
--                              endpoint creates a `production` stack from a
--                              `staging` stack, the new row points back at
--                              the source via parent_stack_id. This is how
--                              the UI groups envs of the "same" app
--                              together.
--   3. Index on (team_id, env, parent_stack_id) so DeployDetailPage can
--      cheaply fetch all envs for a given stack family.
--
-- Rollback (kept as a comment for the runbook — do NOT execute as part of the
-- migration; reverse-migration tooling will run it explicitly):
--   ALTER TABLE stacks DROP COLUMN IF EXISTS parent_stack_id;
--   ALTER TABLE stacks DROP COLUMN IF EXISTS env;
--   DROP INDEX IF EXISTS idx_stacks_env_family;

ALTER TABLE stacks
    ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production';

ALTER TABLE stacks
    ADD COLUMN IF NOT EXISTS parent_stack_id UUID
        REFERENCES stacks(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_stacks_env_family
    ON stacks (team_id, parent_stack_id, env);

CREATE INDEX IF NOT EXISTS idx_stacks_env
    ON stacks (team_id, env);
