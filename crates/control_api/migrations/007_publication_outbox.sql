-- Durable retry queue for authoritative zone publication. Jobs identify a zone,
-- not a proposed record snapshot. A retry always regenerates from committed DB
-- state, so it cannot resurrect a mutation that was rolled back.
CREATE TABLE IF NOT EXISTS publication_outbox (
    zone_domain TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','failed')),
    next_attempt TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE publication_outbox ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';

CREATE INDEX IF NOT EXISTS idx_publication_outbox_due
    ON publication_outbox(next_attempt);
