-- Migration: 021_admin_promo_codes — single-use promo codes issued by a
-- platform admin via POST /api/v1/admin/customers/:team_id/promo.
--
-- Distinct from the plans-yaml promotion definitions (which are static,
-- server-config-level, "everyone gets 10% in November" rules). This table
-- stores single-use admin-issued codes scoped to one team, so they can be
-- audited, expired, and redemption-marked at runtime.
CREATE TABLE IF NOT EXISTS admin_promo_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT UNIQUE NOT NULL,
    team_id         UUID REFERENCES teams(id) ON DELETE CASCADE,
    issued_by_email TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('percent_off', 'first_month_free', 'amount_off')),
    value           INTEGER NOT NULL,
    applies_to      INTEGER,
    used_at         TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lookup index for redemption path: filters out already-used codes so the
-- index stays small. Partial index = only unused rows are indexed.
CREATE INDEX IF NOT EXISTS idx_admin_promo_codes_code ON admin_promo_codes(code) WHERE used_at IS NULL;

-- Reverse lookup so /api/v1/admin/customers/:team_id can list a team's
-- issued codes without a sequential scan.
CREATE INDEX IF NOT EXISTS idx_admin_promo_codes_team ON admin_promo_codes(team_id);
