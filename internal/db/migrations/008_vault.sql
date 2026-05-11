-- Migration: 008_vault
-- Per-team encrypted secret storage.
-- Secrets are versioned: writes always insert a new row. Reads return the latest version
-- by default; specific historical versions are addressable via (team_id, env, key, version).
-- Cross-team queries return zero rows: handlers map that to 404 (never 403) to avoid
-- leaking existence of foreign secrets.

CREATE TABLE IF NOT EXISTS vault_secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    env             TEXT NOT NULL DEFAULT 'production',
    key             TEXT NOT NULL,
    encrypted_value BYTEA NOT NULL,    -- AES-256-GCM(AES_KEY env var, plaintext, nonce)
    version         INT NOT NULL DEFAULT 1,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, env, key, version)
);

CREATE INDEX IF NOT EXISTS idx_vault_secrets_lookup ON vault_secrets (team_id, env, key);

CREATE TABLE IF NOT EXISTS vault_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    team_id     UUID NOT NULL,
    user_id     UUID,
    action      TEXT NOT NULL,             -- 'set' | 'get' | 'delete' | 'rotate' | 'list'
    env         TEXT NOT NULL,
    secret_key  TEXT NOT NULL,
    ip          TEXT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_audit_team_ts ON vault_audit_log (team_id, ts DESC);
