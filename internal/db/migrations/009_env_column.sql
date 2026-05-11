-- 009_env_column.sql — Multi-environment support (dev/staging/production per project)
--
-- Adds an `env` column to resources and deployments so a single team can run
-- dev/staging/prod side-by-side, each getting its own resources and deployments.
-- Existing rows are backfilled to 'production' via the column DEFAULT.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS make
-- this safe to apply twice. New env values are validated by the API layer
-- (^[a-z0-9-]{1,32}$); the schema deliberately keeps env as plain TEXT so
-- adding a new env name never requires a migration.

ALTER TABLE resources   ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production';
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS env TEXT NOT NULL DEFAULT 'production';

CREATE INDEX IF NOT EXISTS idx_resources_team_env   ON resources   (team_id, env);
CREATE INDEX IF NOT EXISTS idx_deployments_team_env ON deployments (team_id, env);
