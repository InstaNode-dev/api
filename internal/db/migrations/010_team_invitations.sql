-- Migration: 010_team_invitations — RBAC roles + token-based invite acceptance
--
-- Adds RBAC role tiers (admin, developer, viewer) on top of the existing
-- owner/member set, plus a single-use token + 7-day expiry on team_invitations
-- so an invitee can accept directly via a tokenized URL (no prior auth required).
--
-- The legacy 002 migration created team_invitations with role IN ('owner','member')
-- and no token / accepted_at columns. This migration:
--   1. drops the old role check (allows admin/developer/viewer)
--   2. backfills a unique token for any existing rows
--   3. enforces token NOT NULL going forward
--   4. adds accepted_at + index on token

-- 0. Ensure pgcrypto is available for gen_random_bytes (used in step 4 backfill).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Loosen role check on team_invitations.
ALTER TABLE team_invitations DROP CONSTRAINT IF EXISTS team_invitations_role_chk;
ALTER TABLE team_invitations
    ADD CONSTRAINT team_invitations_role_chk
    CHECK (role IN ('owner', 'admin', 'developer', 'viewer', 'member'));

-- 2. Loosen role check on users (allow new RBAC roles in users.role).
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'users' AND constraint_name = 'users_role_chk'
    ) THEN
        EXECUTE 'ALTER TABLE users DROP CONSTRAINT users_role_chk';
    END IF;
END$$;
ALTER TABLE users
    ADD CONSTRAINT users_role_chk
    CHECK (role IN ('owner', 'admin', 'developer', 'viewer', 'member'));

-- 3. Add token + accepted_at columns. Tokens are 32-byte hex (64 chars).
ALTER TABLE team_invitations ADD COLUMN IF NOT EXISTS token TEXT;
ALTER TABLE team_invitations ADD COLUMN IF NOT EXISTS accepted_at TIMESTAMPTZ;

-- 4. Backfill tokens for any existing rows.
UPDATE team_invitations
SET token = encode(gen_random_bytes(32), 'hex')
WHERE token IS NULL;

-- 5. Lock down token NOT NULL + uniqueness.
ALTER TABLE team_invitations ALTER COLUMN token SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_token ON team_invitations (token);
