-- Relative deterministic target selection weight among otherwise equivalent rules.
ALTER TABLE georules
    ADD COLUMN IF NOT EXISTS weight INT NOT NULL DEFAULT 1;
