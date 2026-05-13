-- Migration: 024_admin_customer_notes — free-text notes per team, written
-- by platform admins via POST /api/v1/admin/customers/:team_id/notes. Surfaces
-- on the admin Customer Detail drawer ("called this customer 2024-05-10, they
-- want pro tier with annual billing"). Hard-deleted on DELETE — notes are
-- reversible by re-typing, so a soft-delete column would add bookkeeping
-- without operator benefit.
--
-- author_email is the admin's JWT email at write time (denormalized rather
-- than a FK to users) so deleting an admin's user row doesn't blow up audit
-- coherence. Same denorm pattern as audit_log.actor.
CREATE TABLE IF NOT EXISTS admin_customer_notes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    body         TEXT NOT NULL,
    author_email TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Composite index on (team_id, created_at DESC) so the per-team list query
-- ("show me all notes for this team, newest first") is a single index scan,
-- not a sort over a sequential read.
CREATE INDEX IF NOT EXISTS idx_admin_customer_notes_team
    ON admin_customer_notes(team_id, created_at DESC);
