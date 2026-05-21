-- 064_forwarder_sent_audit_fk.sql — close gap #6 (forwarder_sent.audit_id
-- has no FK to audit_log(id), so a team-deletion cascade leaves orphan
-- ledger rows pointing at non-existent audit_log rows).
--
-- BACKGROUND
--
-- forwarder_sent.audit_id is TEXT PRIMARY KEY (migration 055). It cannot
-- carry a direct ON DELETE SET NULL FK against audit_log(id) for three
-- independent reasons:
--
--   1. Type mismatch. audit_log.id is UUID, forwarder_sent.audit_id is
--      TEXT. A FOREIGN KEY constraint requires matching types.
--   2. PK cannot be SET NULL. audit_id is the table's PRIMARY KEY
--      (NOT NULL by definition). ON DELETE SET NULL would violate the
--      PK on every audit_log delete.
--   3. Legacy placeholders. Several legacy emit sites (resource-reminder
--      builders, propagation drivers) write synthetic placeholder values
--      like `reminder-<resource_id>-<stage>` or `provider-<grace_id>`
--      into audit_id. A strict FK would reject those rows at insert time.
--
-- Migration 063 documented this and added a partial regex-shaped index
-- but no actual constraint, so orphans still accumulate.
--
-- STRATEGY
--
-- Add a NEW nullable column `audit_log_id UUID REFERENCES audit_log(id)
-- ON DELETE SET NULL`. This gives us the strict FK relationship gap #6
-- asks for, WITHOUT breaking legacy emit sites (placeholder rows simply
-- leave audit_log_id NULL).
--
--   * audit_id stays as-is — the PK + idempotency key, never touched.
--   * audit_log_id is the new strict-FK breadcrumb. When the worker
--     emits an event whose audit_id IS a real audit_log.id (the modern
--     path), it should also populate audit_log_id with the same value
--     cast to UUID. The forwarder write site will be updated in a
--     follow-up PR to write both columns; this migration is additive
--     only and does not require any application change to be safe.
--   * Backfill: any existing forwarder_sent row whose audit_id is a
--     valid UUID AND exists in audit_log gets audit_log_id populated.
--     Placeholder rows leave audit_log_id NULL — semantically correct
--     because they were never tied to an audit_log row in the first
--     place.
--   * Orphan cleanup: rows whose audit_id was a real UUID but whose
--     audit_log row has since been deleted (via team-deletion cascade)
--     are the orphans gap #6 describes. After this migration runs they
--     will have audit_log_id = NULL (because the JOIN in step 2 won't
--     match), which is the same state placeholder rows are in — the
--     audit_log breadcrumb is gone, but the ledger row's classification
--     + delivery semantics are preserved (the email-truth-surface
--     requirement, CLAUDE.md rule 12).
--
-- Once application code writes audit_log_id on insert (follow-up PR),
-- the FK takes over: future audit_log row deletes automatically set
-- audit_log_id = NULL via ON DELETE SET NULL, no orphan accumulation,
-- no sweeper required.
--
-- ROLLBACK
--
-- ALTER TABLE forwarder_sent DROP CONSTRAINT IF EXISTS forwarder_sent_audit_log_id_fkey;
-- ALTER TABLE forwarder_sent DROP COLUMN IF EXISTS audit_log_id;

BEGIN;

-- Step 1: add the new nullable UUID column. No default — rows are NULL
-- by default; backfill in step 2 populates the subset we can resolve.
ALTER TABLE forwarder_sent
    ADD COLUMN IF NOT EXISTS audit_log_id UUID NULL;

-- Step 2: add the strict FK with ON DELETE SET NULL. Future audit_log
-- deletes will null out audit_log_id rather than orphan the row. This
-- runs before the backfill so the constraint is in place when we
-- populate; the backfill SELECTs only existing audit_log rows so the
-- constraint trivially holds during the UPDATE.
ALTER TABLE forwarder_sent
    ADD CONSTRAINT forwarder_sent_audit_log_id_fkey
    FOREIGN KEY (audit_log_id) REFERENCES audit_log(id) ON DELETE SET NULL;

-- Step 3: backfill audit_log_id from the subset of audit_id values
-- whose shape is a real UUID and whose target audit_log row still
-- exists. Placeholder rows + orphan rows both leave audit_log_id NULL.
-- The regex matches the canonical 8-4-4-4-12 hex UUID shape (same
-- regex migration 063 uses for its partial index).
UPDATE forwarder_sent fs
   SET audit_log_id = al.id
  FROM audit_log al
 WHERE fs.audit_log_id IS NULL
   AND fs.audit_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND al.id = fs.audit_id::uuid;

-- Step 4: index for the orphan-reconciler join shape. Lets the worker
-- ask "show me ledger rows whose audit_log_id is NULL but whose
-- audit_id IS a real UUID" — that's exactly the orphan set.
CREATE INDEX IF NOT EXISTS idx_forwarder_sent_audit_log_id_not_null
    ON forwarder_sent (audit_log_id)
 WHERE audit_log_id IS NOT NULL;

-- Step 5: document the column relationship so a future operator
-- reading the schema understands the migration intent.
COMMENT ON COLUMN forwarder_sent.audit_log_id IS
    'Strict-FK breadcrumb to audit_log.id (UUID) with ON DELETE SET NULL. '
    'NULL when (a) the source emit site used a placeholder audit_id (legacy '
    'resource-reminder builders, propagation drivers) or (b) the referenced '
    'audit_log row has since been deleted (e.g. team-deletion cascade). '
    'Added 2026-05-21 by migration 064 to close gap #6 (orphan ledger rows '
    'accumulating after team-deletion cascades). audit_id remains the PK + '
    'idempotency key; audit_log_id is the join column for support queries '
    'that need to walk back to the audit_log row.';

COMMIT;
