-- Migration: 024_resources_paused_status
--
-- Add a `paused` status for resources. Customers can pause a resource to stop
-- it counting against the resource-count quota while preserving the data and
-- the connection URL. Resume flips status back to `active` with no re-issued
-- credentials.
--
-- Iron rules:
--   - Storage usage of paused resources STILL counts against the per-team
--     storage cap (so pause-and-bloat is not a valid escape hatch).
--   - Resource-count quotas (per-type caps in plans.yaml) exclude paused
--     rows — pausing is "stop billing the slot, keep the data."
--   - paused_at is set on transition active → paused and cleared on
--     transition paused → active. Reading paused_at is how the worker /
--     dashboard distinguish "paused 2h ago" from "paused 90 days ago".
--
-- The check-constraint was named `resources_status_check` implicitly by
-- Postgres in earlier migrations; dropping IF EXISTS is safe across fresh
-- schemas (test runner that never created the constraint) and existing
-- production schemas (where it was implicit). After the drop the new
-- constraint is added that includes 'paused' as a permitted value.

ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_status_check;
ALTER TABLE resources
    ADD CONSTRAINT resources_status_check
    CHECK (status IN ('active', 'paused', 'expired', 'deleted'));

ALTER TABLE resources ADD COLUMN IF NOT EXISTS paused_at TIMESTAMPTZ;

-- Partial index narrows the scan to paused rows only — the dashboard's
-- "Paused Resources" tab and the billing-state aggregator both filter by
-- status = 'paused', so a partial index is the right shape.
CREATE INDEX IF NOT EXISTS idx_resources_paused
    ON resources (paused_at)
    WHERE status = 'paused';
