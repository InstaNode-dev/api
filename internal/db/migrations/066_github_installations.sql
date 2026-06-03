-- 066_github_installations.sql — GitHub App installations, P4.1.
--
-- WHY: P4 adds install-once push-to-deploy on top of the existing manual
-- per-repo webhook (app_github_connections). When a team installs the InstaNode
-- GitHub App, GitHub assigns an installation_id; we persist the installation↔team
-- link so that (a) the install/callback flow can bind it, (b) the App webhook can
-- resolve an incoming push's installation_id → owning team before acting, and
-- (c) the token-minter can mint a short-lived installation access token for
-- private-repo clones.
--
-- We store ONLY the installation_id + account metadata — never an access token
-- (those are minted on demand from the App private key and cached in Redis, 1h
-- TTL). suspended_at is set when GitHub sends an installation `suspend` event so
-- the webhook can stop acting without deleting the row.

CREATE TABLE IF NOT EXISTS github_installations (
    installation_id BIGINT PRIMARY KEY,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    account_login   TEXT NOT NULL DEFAULT '',  -- the org/user the App is installed on
    suspended_at    TIMESTAMPTZ,               -- non-NULL → installation suspended
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A team may have multiple installations (personal + orgs); look them up by team.
CREATE INDEX IF NOT EXISTS idx_github_installations_team ON github_installations(team_id);
