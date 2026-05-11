-- Migration: 013_magic_links — passwordless email login.
--
-- Purpose: GitHub/Google OAuth covers most of the dashboard login surface, but
-- a fair chunk of agent-installed users (curl/MCP) only have an email address.
-- A magic-link flow gives them a one-click sign-in without a password.
--
-- Format: clients see a plaintext token shaped like mlnk_<32-byte-base64url>
-- (~47 chars) embedded as the ?t= parameter on a callback URL we email out.
-- We store only the SHA-256 of the plaintext; the user's mailbox is the only
-- copy.
--
-- Single-use: consumed_at is set on the first /auth/email/callback hit. A
-- second click on the same link returns 400 (link already used).
--
-- TTL: expires_at is created+15min. Anything past that is rejected even if
-- consumed_at is NULL.

CREATE TABLE IF NOT EXISTS magic_links (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email        TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,        -- SHA-256 of the plaintext token
    return_to    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,        -- 15 min from creation
    consumed_at  TIMESTAMPTZ,                 -- single-use; set on first /callback
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links (token_hash) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_magic_links_email ON magic_links (email, created_at DESC);
