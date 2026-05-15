-- 047_resources_applied_conn_limit.sql
--
-- Phase 1 of the resource regrade / entitlement-reconciliation work
-- (see api/SPEC-resource-regrade-autoscaling.md §12).
--
-- A plan upgrade flips resources.tier (ElevateResourceTiersByTeam) but never
-- re-applies the HARD infrastructure limits baked at provision time — the
-- Postgres role CONNECTION LIMIT in particular. This column records the
-- connection cap currently APPLIED on the provisioned resource so the
-- entitlement reconciler can detect drift (applied != tier entitlement) and
-- skip no-op re-grades.
--
-- Column:
--   applied_conn_limit  INT NULL
--                       The Postgres role CONNECTION LIMIT last applied to
--                       this resource (-1 = unlimited). NULL = never re-graded
--                       / unknown — the reconciler treats NULL as "needs a
--                       grade" and reconciles it on the next sweep.
--
-- Idempotent: ADD COLUMN IF NOT EXISTS so re-running the migration is safe.

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS applied_conn_limit INT;

-- Partial index for the reconciler's drift sweep: it scans active, non-expired
-- postgres resources and compares applied_conn_limit against the tier entitlement.
CREATE INDEX IF NOT EXISTS resources_regrade_sweep_idx
    ON resources (team_id)
 WHERE resource_type = 'postgres' AND status = 'active';
