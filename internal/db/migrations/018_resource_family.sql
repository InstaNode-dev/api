-- Migration: 018_resource_family
-- Slice 2 of env-aware deployments — adds parent_resource_id so resources can
-- form env-twin families (prod-db ↔ staging-db ↔ dev-db). The family root is
-- the row whose parent_resource_id IS NULL; siblings share parent_resource_id
-- pointing at the root id.
--
-- ON DELETE SET NULL: deleting the root promotes its children to roots of
-- their own single-member families instead of cascading-deleting them.
--
-- Partial unique index uq_resources_family_env enforces "at most one twin
-- per env per family" at the schema level — handlers double-check at the
-- request layer for friendlier 409s.

ALTER TABLE resources
  ADD COLUMN IF NOT EXISTS parent_resource_id UUID REFERENCES resources(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_resources_family
  ON resources (parent_resource_id)
  WHERE parent_resource_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_resources_family_env
  ON resources (parent_resource_id, env)
  WHERE parent_resource_id IS NOT NULL;
