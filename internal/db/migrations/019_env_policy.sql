-- 019_env_policy.sql — Per-environment access policy on the team row.
--
-- Slice 6 of ENV-AWARE-DEPLOYMENTS-DESIGN. Adds a JSONB column on teams that
-- gates write-mutating actions on a given env (deploy, delete_resource,
-- vault_write) by the user's team role.
--
-- Shape:
--   {
--     "production": { "deploy": ["owner"], "delete_resource": ["owner"], "vault_write": ["owner"] },
--     "staging":    { "deploy": ["owner","developer"] }
--   }
--
-- Default '{}'::jsonb means **no policy** — every action by every role is
-- allowed. This is the critical backward-compat guarantee: a team that never
-- touches env_policy keeps today's behaviour. The RequireEnvAccess middleware
-- short-circuits on an empty policy object (or an empty role-list for the
-- action being checked) so an accidentally-misconfigured team can never get
-- locked out of their own production env.
--
-- Rollback (NOT executed — kept for runbook only):
--   ALTER TABLE teams DROP COLUMN IF EXISTS env_policy;

ALTER TABLE teams
  ADD COLUMN IF NOT EXISTS env_policy JSONB NOT NULL DEFAULT '{}'::jsonb;
