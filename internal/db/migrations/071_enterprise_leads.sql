-- enterprise_leads: captures contact details from pricing-page "Talk to us"
-- form for Team/Enterprise prospects. Replaces the mailto: link with a
-- durable, queryable lead record. team_id is nullable because most submitters
-- are unauthenticated visitors (anonymous or free tier); authenticated callers
-- self-identify so we can skip duplicate outreach.
--
-- Wave-3 task A5: POST /api/v1/leads (public endpoint, no auth required).
-- Notification email to contact@instanode.dev is emitted by the
-- event_email_forwarder worker job via an audit_log kind="lead.captured" row.

CREATE TABLE IF NOT EXISTS enterprise_leads (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT        NOT NULL,
    name       TEXT,
    company    TEXT,
    use_case   TEXT,
    -- team_id links the lead to an authenticated team when the submitter is
    -- logged in. ON DELETE SET NULL so team deletion does not orphan the lead.
    team_id    UUID        REFERENCES teams(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Supports "new leads in the last 24h" dashboard queries and keeps the
-- INSERT path cheap (no lock contention on PK index for time-ordered reads).
CREATE INDEX IF NOT EXISTS enterprise_leads_created_at_idx ON enterprise_leads (created_at DESC);
-- Prevents duplicate submission from the same email (common with retry-happy
-- forms). Duplicate submits within the same day are silently deduplicated via
-- ON CONFLICT DO NOTHING at the application layer.
CREATE INDEX IF NOT EXISTS enterprise_leads_email_idx ON enterprise_leads (email);
