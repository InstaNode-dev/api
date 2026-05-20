-- Migration: 060_resources_auth_mode
--
-- Add resources.auth_mode column for the NATS per-tenant isolation cutover
-- (MR-P0-5 — held architecture P0, 2026-05-20). See
-- NATS-ISOLATION-MIGRATION-2026-05-20.md for the full rationale.
--
-- Background:
--   NATS in `instant-data` runs unauthenticated. Any pod on the cluster can
--   dial nats://nats.instant-data.svc.cluster.local:4222 and read/write every
--   other tenant's subjects + JetStream streams. The "subject prefix derived
--   from token" pattern is naming convention, not isolation.
--
--   Cutover plan: switch NATS to operator mode (per-tenant accounts with
--   signed user JWTs). The handler + provisioner code lands first and
--   gracefully degrades to the unauthenticated path while operator keys
--   are generated. Then operator flips nats.yaml + applies nats-operator
--   Secret; new provisions mint accounts; existing queue rows stay
--   grandfathered until they recycle.
--
-- This migration:
--   - Adds resources.auth_mode TEXT NOT NULL DEFAULT 'isolated' with a CHECK.
--   - Backfills every PRE-cutover queue row to auth_mode='legacy_open' so
--     the api can keep returning the (un-creds) URL for them until they
--     expire/get-recycled, without re-issuing isolated credentials we have
--     no way to revoke later.
--   - Adds resources.queue_account_seed_encrypted TEXT NULL — encrypted at
--     rest (AES-256-GCM with the same AES_KEY as connection_url), used by
--     the provisioner teardown path to re-sign the revocation claim after a
--     restart.
--
-- Backfill rule:
--   For queue resources only — every other resource_type ('postgres',
--   'redis', etc.) keeps auth_mode='isolated' (their default), since auth
--   has worked since day one for those backends. The column is added to ALL
--   rows so handler code can read it uniformly without per-type branching.
--
-- Rollback:
--   ALTER TABLE resources DROP COLUMN auth_mode;
--   ALTER TABLE resources DROP COLUMN queue_account_seed_encrypted;
--   (Safe — no other code or constraint references these.)

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT 'isolated';

ALTER TABLE resources DROP CONSTRAINT IF EXISTS resources_auth_mode_check;
ALTER TABLE resources
    ADD CONSTRAINT resources_auth_mode_check
    CHECK (auth_mode IN ('isolated', 'legacy_open'));

ALTER TABLE resources
    ADD COLUMN IF NOT EXISTS queue_account_seed_encrypted TEXT;

-- Backfill: every PRE-cutover queue row (created_at < NOW() at apply time) is
-- grandfathered as legacy_open. Idempotent — re-runs only touch rows still
-- marked 'isolated' (the default), which is fine because the column was just
-- added with that default, so the first run hits every queue row exactly once
-- and subsequent runs are no-ops.
UPDATE resources
   SET auth_mode = 'legacy_open'
 WHERE resource_type = 'queue'
   AND auth_mode = 'isolated'
   AND created_at < NOW();

-- Index for the worker reaper sweep "find legacy_open queue rows ready to
-- recycle". Partial index — only the rows we care about, cheap to maintain.
CREATE INDEX IF NOT EXISTS idx_resources_legacy_open_queue
    ON resources (resource_type, auth_mode, created_at)
    WHERE auth_mode = 'legacy_open' AND status = 'active';
