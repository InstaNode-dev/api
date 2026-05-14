-- 043_backup_sha256.sql — FIX-H (#59 B36): backup integrity column.
--
-- Adds a sha256 TEXT column to resource_backups so the restore handler
-- can verify the gzipped pg_dump artifact hasn't bit-rotted between the
-- backup taking and the restore replay. The worker (customer_backup_runner)
-- computes the digest while streaming the gzipped dump to S3 and stores
-- it on the row at finalize time. The restore handler re-reads the S3
-- object, recomputes the digest, and compares — mismatch returns 500
-- backup_integrity_failed with an operator-contact agent_action.
--
-- Hex-encoded (64 chars) so the column is human-greppable in operator
-- queries; nullable because every historical row pre-dating this
-- migration has no digest and the restore handler treats NULL as
-- "unknown integrity — skip the check" (fail-open on legacy rows, fail-
-- closed on mismatch for new rows).

ALTER TABLE resource_backups ADD COLUMN IF NOT EXISTS sha256 TEXT;
