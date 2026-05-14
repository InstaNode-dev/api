-- Migration: 035_app_github_connections — GitHub auto-deploy.
--
-- Lets a customer wire a deployment to a GitHub repo + branch. When the
-- branch receives a push, GitHub POSTs to
-- /webhooks/github/:webhook_id, the API verifies the HMAC-SHA256
-- signature, and enqueues a fresh deploy from the repo's tarball.
--
-- Columns:
--   id              UUID — primary key. Doubles as the public webhook_id
--                   the customer pastes into GitHub (so we never need a
--                   second indirection table).
--   app_id          UUID — FK to deployments.app_id is impractical because
--                   app_id is TEXT, not UUID; we point at deployments.id
--                   instead so the join is a clean UUID = UUID.
--   team_id         UUID — denormalised for cheap WHERE filtering on the
--                   /api/v1/deployments/:id/github reads (avoids a JOIN
--                   on every read).
--   github_repo     TEXT — "owner/repo" form. Validated on write.
--   branch          TEXT — default 'main'. Pushes to other branches are
--                   ignored at receive time (no-op + 200 to acknowledge).
--   webhook_secret  TEXT — AES-256-GCM ciphertext of the HMAC-SHA256
--                   signing key generated at connect time. Decrypted on
--                   every receive to verify X-Hub-Signature-256.
--   installation_id BIGINT — optional GitHub App installation id. Today
--                   we use plain webhooks (customer-pasted), so this is
--                   NULL; reserved for a future GitHub App where
--                   installation_id is how we authenticate the tarball
--                   fetch against private repos.
--   last_deploy_at  TIMESTAMPTZ — bumped on every successful enqueue.
--   last_commit_sha TEXT — the commit we last enqueued a deploy for.
--                   Idempotency gate: if a duplicate push.event with the
--                   same `after` arrives, we no-op.
--
-- Unique index on app_id: an app has at most one GitHub connection. A
-- customer who wants to switch repos deletes + re-creates — the secret
-- rotates, the user re-pastes the webhook URL in GitHub.

CREATE TABLE IF NOT EXISTS app_github_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id          UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    github_repo     TEXT NOT NULL,
    branch          TEXT NOT NULL DEFAULT 'main',
    webhook_secret  TEXT NOT NULL,
    installation_id BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_deploy_at  TIMESTAMPTZ,
    last_commit_sha TEXT
);

-- One connection per app — the dashboard / agents treat (app_id) as
-- the natural key for the connection.
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_github_connection
    ON app_github_connections(app_id);

-- Cheap team scope on the /api/v1/deployments/:id/github reads.
CREATE INDEX IF NOT EXISTS idx_app_github_connections_team
    ON app_github_connections(team_id);

-- pending_github_deploys — work queue the worker drains. The api inserts a
-- row on every accepted push.event; the worker picks it up, downloads the
-- tarball from the github archive URL, and calls back to /deploy/:id/redeploy
-- (or the equivalent internal hook) to actually rebuild.
--
-- status enum: 'queued' → 'in_progress' → 'completed' | 'failed'.
-- attempts caps at 3 (transient github 5xx); a 4xx from github archive is
-- permanent (likely permissions / deleted ref) and goes straight to 'failed'.
CREATE TABLE IF NOT EXISTS pending_github_deploys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id   UUID NOT NULL REFERENCES app_github_connections(id) ON DELETE CASCADE,
    app_id          UUID NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    commit_sha      TEXT NOT NULL,
    pusher_login    TEXT,
    status          TEXT NOT NULL DEFAULT 'queued',
    attempts        INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    enqueued_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- Worker scan index — partial so the index stays tiny once the bulk of
-- rows are 'completed'.
CREATE INDEX IF NOT EXISTS idx_pending_github_deploys_queued
    ON pending_github_deploys(enqueued_at)
    WHERE status = 'queued';

-- (connection_id, commit_sha) is the idempotency tuple — if the worker
-- has already enqueued + processed a given commit, the receive handler
-- can short-circuit. Not UNIQUE because retry / requeue flows may
-- legitimately insert a second row.
CREATE INDEX IF NOT EXISTS idx_pending_github_deploys_commit
    ON pending_github_deploys(connection_id, commit_sha);
