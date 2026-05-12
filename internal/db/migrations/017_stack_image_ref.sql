-- 017_stack_image_ref.sql — Persist the built image reference per stack service.
--
-- The /api/v1/stacks/:slug/promote endpoint copies a source stack's image
-- reference onto the target sibling so the target can be deployed WITHOUT
-- re-building from a tarball. Until this migration the build step (kaniko
-- via the k8s compute provider) produced an image reference that was never
-- persisted anywhere — making promote a compute no-op and forcing every
-- target environment to either rebuild from a tarball it doesn't have or
-- silently fail to deploy.
--
-- Schema:
--   stack_services.image_ref TEXT  — fully-qualified docker image reference
--                                    returned by the build provider after a
--                                    successful build. NULL for pre-migration
--                                    rows; promotes for those stacks return
--                                    412 with an agent_action telling the
--                                    user to redeploy the source first.
--
-- Why per-service (not per-stack): every service in a stack builds its own
-- image. Two services in the same stack will always have DIFFERENT image
-- references (different svc names → different tags). A stack-level column
-- would force every promote to either rebuild all services or fall back to
-- the per-service value anyway, so we store the per-service value directly.
--
-- The partial index on (image_ref) where NOT NULL keeps the index small
-- (most rows during the cutover have NULL); used by promote to look up a
-- stack's image refs.
--
-- Rollback (NOT executed as part of this migration — kept for runbook only):
--   DROP INDEX IF EXISTS idx_stack_services_image_ref;
--   ALTER TABLE stack_services DROP COLUMN IF EXISTS image_ref;

ALTER TABLE stack_services ADD COLUMN IF NOT EXISTS image_ref TEXT;
CREATE INDEX IF NOT EXISTS idx_stack_services_image_ref ON stack_services (image_ref)
  WHERE image_ref IS NOT NULL;
