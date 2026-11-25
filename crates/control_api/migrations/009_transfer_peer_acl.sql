-- Exact source-IP allowlist for zone transfers. Empty preserves policy-only behavior.
ALTER TABLE zones
    ADD COLUMN IF NOT EXISTS axfr_allowed_peers TEXT[] NOT NULL DEFAULT '{}';
