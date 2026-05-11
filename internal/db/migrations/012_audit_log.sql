-- Migration: 012_audit_log — per-team event stream consumed by the
-- dashboard's Recent Activity feed.
CREATE TABLE IF NOT EXISTS audit_log (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    actor        TEXT NOT NULL DEFAULT 'agent',  -- 'agent' / 'user' / 'system' / 'cli'
    kind         TEXT NOT NULL,                  -- provision / claim / rotate / delete / deploy / vault.put / vault.delete / login
    resource_type TEXT,                          -- postgres / redis / mongodb / queue / storage / webhook / deploy / pat / null
    resource_id  UUID,
    summary      TEXT NOT NULL,                  -- short HTML-safe text the UI renders verbatim
    metadata     JSONB,                          -- arbitrary k/v: cloud_vendor, country, ip_prefix, ...
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_team_at ON audit_log (team_id, created_at DESC);
