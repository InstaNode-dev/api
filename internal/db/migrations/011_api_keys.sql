-- Migration: 011_api_keys — long-lived Personal Access Tokens for agents/CI.
--
-- Purpose: a 1-hour browser-bound JWT is hostile to:
--   - agents (Claude Code, Cursor) that need to call the API across days
--   - CI workflows that provision ephemeral resources per PR
--   - founders who paste a token into .env and forget about it
--
-- Format: clients see ink_<32-byte-base64url> (~50 chars total). The literal
-- "ink_" prefix lets the auth middleware distinguish a PAT from a JWT without
-- parsing the token. Only the SHA-256 of the token is stored; the plaintext
-- is shown exactly once at creation time.
--
-- Scopes: 'read' (GET endpoints), 'write' (provision/deploy mutations),
-- 'admin' (team + billing). Hierarchy: admin > write > read. Stored as a
-- text array so callers can grant compound scopes if needed later.

CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    scopes       TEXT[] NOT NULL DEFAULT ARRAY['read','write']::TEXT[],
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_team_id ON api_keys (team_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys (key_hash) WHERE revoked_at IS NULL;
