-- 005_stacks_anon.sql — Allow anonymous (unauthenticated) stack deploys.
-- Anonymous stacks have team_id = NULL, expires_at set to now()+24h,
-- and a fingerprint for dedup — same model as anonymous resource provisions.

-- Make team_id nullable (anonymous users have no team).
ALTER TABLE stacks ALTER COLUMN team_id DROP NOT NULL;

-- Add expires_at for TTL (anonymous stacks expire in 24h).
ALTER TABLE stacks ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

-- Add fingerprint (SHA256 of /24 subnet + ASN) for anonymous dedup.
ALTER TABLE stacks ADD COLUMN IF NOT EXISTS fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_stacks_expires ON stacks(expires_at)
    WHERE expires_at IS NOT NULL AND status NOT IN ('deleted', 'deleting');
