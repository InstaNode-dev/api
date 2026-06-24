-- 072_forwarder_sent_audit_log_fk.sql
--
-- Adds a real UUID foreign key column to forwarder_sent so the orphan-
-- reconciler and team-deletion cascade can use a proper JOIN instead of
-- regex-based TEXT comparison.
--
-- WHY NOT JUST A FK ON audit_id
-- forwarder_sent.audit_id is TEXT on purpose: legacy emit sites write
-- synthetic placeholder values ("reminder-<resource_id>-<stage>",
-- "provider-<grace_id>") that cannot be parsed as UUIDs. A FK on the
-- TEXT column would reject every one of those rows (see mig 063 comment
-- for the full rationale). This migration adds a SEPARATE nullable UUID
-- column (audit_log_id) that the worker populates only when audit_id IS
-- a real UUID — old rows and placeholder-id rows keep NULL, which is safe.
--
-- WIRE-UP REQUIRED
-- The worker's event_email_forwarder must set audit_log_id = audit_id::uuid
-- when it inserts a new row whose audit_id matches the UUID regex. That
-- change ships in the companion worker PR. Until then, existing rows and
-- new rows from placeholder-id emitters will have audit_log_id = NULL.
--
-- BACKFILL
-- A one-time UPDATE backfills all existing rows whose audit_id is UUID-
-- shaped. This is safe: the partial index from mig 063 makes the scan
-- instant; ON DELETE SET NULL means team deletion remains non-destructive.
--
-- ROLLBACK
-- ALTER TABLE forwarder_sent DROP COLUMN IF EXISTS audit_log_id;

BEGIN;

ALTER TABLE forwarder_sent
    ADD COLUMN IF NOT EXISTS audit_log_id UUID
        REFERENCES audit_log(id) ON DELETE SET NULL;

-- Back-fill existing rows whose audit_id is already a UUID.
-- The partial index from mig 063 keeps this UPDATE fast even on large tables.
UPDATE forwarder_sent
   SET audit_log_id = audit_id::uuid
 WHERE audit_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND audit_log_id IS NULL
   AND EXISTS (SELECT 1 FROM audit_log al WHERE al.id = audit_id::uuid);

CREATE INDEX IF NOT EXISTS idx_forwarder_sent_audit_log_id
    ON forwarder_sent (audit_log_id)
 WHERE audit_log_id IS NOT NULL;

COMMIT;
