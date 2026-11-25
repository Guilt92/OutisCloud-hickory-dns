-- Preserve the publishable, non-ownership configuration with each zone revision.
CREATE TABLE IF NOT EXISTS zone_revisions (
    id UUID PRIMARY KEY,
    zone_id UUID NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    records JSONB NOT NULL,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason TEXT NOT NULL DEFAULT 'change',
    user_id UUID,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_zone_revisions_zone ON zone_revisions(zone_id, created_at DESC);
ALTER TABLE zone_revisions
    ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}'::jsonb;
