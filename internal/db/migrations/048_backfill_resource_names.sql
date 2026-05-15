-- 048_backfill_resource_names.sql
--
-- Mandatory resource naming (BREAKING contract change — 2026-05-16).
--
-- `name` is now STRICTLY REQUIRED on every provisioning endpoint, so the
-- dashboard no longer renders raw hashes like `db_fcb890cde09d`. Existing
-- rows provisioned before this change still have a NULL or empty `name` —
-- this migration backfills them with readable per-team sequential labels so
-- the dashboard has something human to show for legacy resources.
--
-- Label shape: "<resource_type> <n>" where n is the 1-based ordinal of that
-- resource among the team's resources of the same type, ordered by
-- created_at. e.g. "postgres 1", "redis 2", "mongodb 1". Anonymous rows
-- (team_id IS NULL) are partitioned together under a NULL team bucket.
--
-- Idempotent: only touches rows where name IS NULL or name = '' (trimmed),
-- so re-running the migration is a no-op for already-named rows.

-- ── resources table ─────────────────────────────────────────────────────────
WITH ranked AS (
    SELECT
        id,
        resource_type
            || ' '
            || row_number() OVER (
                   PARTITION BY team_id, resource_type
                   ORDER BY created_at, id
               ) AS generated_name
    FROM resources
    WHERE name IS NULL OR btrim(name) = ''
)
UPDATE resources r
   SET name = ranked.generated_name
  FROM ranked
 WHERE r.id = ranked.id;

-- ── deployments table ───────────────────────────────────────────────────────
-- Deployments store their human label inside env_vars->>'_name' (there is no
-- dedicated name column — see api/internal/handlers/deploy.go). Backfill the
-- same readable per-team sequential label for any deployment missing it.
WITH ranked_deploys AS (
    SELECT
        id,
        'deployment '
            || row_number() OVER (
                   PARTITION BY team_id
                   ORDER BY created_at, id
               ) AS generated_name
    FROM deployments
    WHERE env_vars->>'_name' IS NULL OR btrim(env_vars->>'_name') = ''
)
UPDATE deployments d
   SET env_vars = jsonb_set(
                      COALESCE(d.env_vars, '{}'::jsonb),
                      '{_name}',
                      to_jsonb(ranked_deploys.generated_name),
                      true
                  )
  FROM ranked_deploys
 WHERE d.id = ranked_deploys.id;
