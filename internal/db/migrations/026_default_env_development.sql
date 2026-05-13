-- 026_default_env_development.sql — flip the column DEFAULT for `env` from
-- 'production' to 'development' on resources, deployments, and stacks.
--
-- WHY: today a caller that omits ?env / "env": ... silently lands in production.
-- New product directive — accidental no-env provisions should go to the
-- lowest-stakes bucket (development), not the same bucket as the team's real
-- prod data. The API-layer default (models.NormalizeEnv + handlers/resolveEnv)
-- is flipped in the same PR; this migration keeps the DB column DEFAULT
-- aligned so a raw-SQL INSERT (e.g. background workers, future internal
-- endpoints) gets the same behaviour without needing to set env explicitly.
--
-- BACKWARD COMPAT: existing rows are NOT touched. The migration only modifies
-- the column DEFAULT — every row already in resources/deployments/stacks keeps
-- whatever env it was created with (typically 'production' for rows that
-- pre-date this change). API callers that explicitly send env="production"
-- continue to work unchanged.
--
-- Idempotency: ALTER COLUMN SET DEFAULT is itself idempotent — re-running this
-- migration is a no-op. Safe to re-apply on every startup.
--
-- Rollback (kept as a comment for the runbook — do NOT execute as part of the
-- migration; reverse-migration tooling will run it explicitly):
--   ALTER TABLE resources   ALTER COLUMN env SET DEFAULT 'production';
--   ALTER TABLE deployments ALTER COLUMN env SET DEFAULT 'production';
--   ALTER TABLE stacks      ALTER COLUMN env SET DEFAULT 'production';

ALTER TABLE resources   ALTER COLUMN env SET DEFAULT 'development';
ALTER TABLE deployments ALTER COLUMN env SET DEFAULT 'development';
ALTER TABLE stacks      ALTER COLUMN env SET DEFAULT 'development';
