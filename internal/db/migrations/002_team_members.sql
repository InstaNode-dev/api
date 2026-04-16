-- Migration: 002_team_members — roles, invitations, team membership

ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'member';

-- Promote earliest member per team to owner when still default 'member'.
UPDATE users u
SET role = 'owner'
FROM (
    SELECT DISTINCT ON (team_id) id
    FROM users
    WHERE team_id IS NOT NULL
    ORDER BY team_id, created_at ASC
) AS first_user
WHERE u.id = first_user.id
  AND u.role = 'member';

CREATE TABLE IF NOT EXISTS team_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    invited_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '7 days',
    CONSTRAINT team_invitations_role_chk CHECK (role IN ('owner', 'member')),
    CONSTRAINT team_invitations_status_chk CHECK (status IN ('pending', 'accepted', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_invitations_team ON team_invitations(team_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email ON team_invitations(lower(email));

CREATE UNIQUE INDEX IF NOT EXISTS idx_invitations_team_email_pending
    ON team_invitations (team_id, lower(email))
    WHERE status = 'pending';
