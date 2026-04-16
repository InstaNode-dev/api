-- 006: store provisioner key_prefix per resource (needed for Redis dedup path)
ALTER TABLE resources ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT '';
