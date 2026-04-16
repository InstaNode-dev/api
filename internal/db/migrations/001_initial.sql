-- Migration: 001_initial
-- Platform schema for instant.dev Phase 1

CREATE TABLE IF NOT EXISTS teams (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT,
    plan_tier         TEXT NOT NULL DEFAULT 'hobby',
    stripe_customer_id TEXT UNIQUE,
    trial_ends_at     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID REFERENCES teams(id) ON DELETE CASCADE,
    email       TEXT UNIQUE NOT NULL,
    github_id   TEXT UNIQUE,
    google_id   TEXT UNIQUE,
    created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resources (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id          UUID REFERENCES teams(id) ON DELETE SET NULL,
    token            UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    resource_type    TEXT NOT NULL,
    name             TEXT,
    connection_url   TEXT,           -- AES-256-GCM encrypted
    tier             TEXT NOT NULL DEFAULT 'anonymous',
    fingerprint      TEXT,
    cloud_vendor     TEXT,
    country_code     CHAR(2),
    status           TEXT NOT NULL DEFAULT 'active',
    migration_status TEXT,
    expires_at       TIMESTAMPTZ,
    storage_bytes    BIGINT DEFAULT 0,
    created_request_id TEXT,
    created_at       TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_resources_token       ON resources(token);
CREATE INDEX IF NOT EXISTS idx_resources_fingerprint ON resources(fingerprint) WHERE team_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_resources_expires     ON resources(expires_at) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_resources_team        ON resources(team_id) WHERE team_id IS NOT NULL;


CREATE TABLE IF NOT EXISTS onboarding_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint     TEXT NOT NULL,
    jwt_issued_at   TIMESTAMPTZ DEFAULT now(),
    jwt_expires_at  TIMESTAMPTZ,
    converted_at    TIMESTAMPTZ,
    team_id         UUID REFERENCES teams(id),
    resource_tokens UUID[],
    jti             TEXT UNIQUE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_onboarding_jti ON onboarding_events(jti);
CREATE INDEX IF NOT EXISTS idx_onboarding_fingerprint ON onboarding_events(fingerprint);
