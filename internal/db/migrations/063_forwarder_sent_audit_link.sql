-- 063_forwarder_sent_audit_link.sql
--
-- B18 hardening (Wave 3 consolidated, 2026-05-21): document the
-- relationship between forwarder_sent.audit_id and audit_log.id, and
-- add a partial-index that lets the worker reconcile orphaned ledger
-- rows ("classification stays in 'success' but no matching audit_log
-- exists") cheaply.
--
-- WHY THIS IS A SOFT FK, NOT A STRICT FK
--
-- forwarder_sent.audit_id is a TEXT column on purpose. Several legacy
-- emit sites (worker reminder builders that pre-date the
-- audit-log-in-Postgres consolidation) pass a synthetic placeholder
-- value (`reminder-<resource_id>-<stage>`, `provider-<grace_id>`)
-- instead of a real audit_log UUID. A FOREIGN KEY constraint would
-- reject those rows; converting every legacy emitter to the real
-- UUID would require a multi-PR refactor we have NOT scheduled.
--
-- Instead this migration:
--   1. Adds a COMMENT ON COLUMN documenting that the column is
--      USUALLY an audit_log.id but MAY be a placeholder, and that the
--      worker's orphan-reconciler must tolerate both shapes.
--   2. Creates a PARTIAL INDEX on the subset of rows whose audit_id is
--      a valid UUID (matches the canonical 8-4-4-4-12 hex shape via
--      regex). This is the set the orphan-reconciler scans; the
--      placeholder rows are excluded so the index stays tight.
--
-- The forwarder_sent table itself was added by migration 055 and
-- enriched by 059/061. This migration is purely additive — no row
-- rewrites, no column rewrites, no FK creation that could cascade.
--
-- ROLLBACK
--
-- DROP INDEX IF EXISTS idx_forwarder_sent_real_audit_id;
-- COMMENT ON COLUMN forwarder_sent.audit_id IS NULL;

BEGIN;

-- Partial index covering only rows whose audit_id is a real UUID.
-- The orphan-reconciler joins forwarder_sent → audit_log on this column
-- and the partial index keeps the join cost bounded by the size of the
-- real-UUID subset (placeholder-id rows skip the join entirely because
-- they can't have a matching audit_log row).
--
-- The regex is intentionally case-insensitive and tolerates the
-- standard 8-4-4-4-12 hex shape Postgres' uuid type emits. We do NOT
-- use ::uuid casts in the index expression because that would error
-- on every placeholder row at write time.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_real_audit_id
    ON forwarder_sent (audit_id)
 WHERE audit_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

-- Document the semantics so a future operator reading the schema does
-- not assume the column is FK-enforced.
COMMENT ON COLUMN forwarder_sent.audit_id IS
    'Usually the matching audit_log.id (UUID) that triggered the email send. '
    'Legacy emit sites (resource-reminder builders, propagation drivers that '
    'predate audit-log centralisation) may write synthetic placeholder values '
    'like "reminder-<resource_id>-<stage>" or "provider-<grace_id>". A strict '
    'FOREIGN KEY would reject those rows, so the link is intentionally soft. '
    'The orphan-reconciler (worker repo) uses idx_forwarder_sent_real_audit_id '
    'to scan only the UUID subset and tolerates placeholder rows on the '
    'non-matched branch.';

COMMIT;
