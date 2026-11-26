-- Persist per-zone denial-of-existence proof parameters for signed zones.
ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_proof_type TEXT NOT NULL DEFAULT 'nsec';
ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_salt TEXT NOT NULL DEFAULT '';
ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_iterations INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS dnssec_nsec3_opt_out BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE zones ADD CONSTRAINT zones_dnssec_proof_type_check
    CHECK (dnssec_proof_type IN ('nsec', 'nsec3'));
ALTER TABLE zones ADD CONSTRAINT zones_dnssec_nsec3_iterations_check
    CHECK (dnssec_nsec3_iterations BETWEEN 0 AND 150);
ALTER TABLE zones ADD CONSTRAINT zones_dnssec_nsec3_salt_hex_check
    CHECK (dnssec_nsec3_salt ~ '^([0-9a-fA-F]{2}){0,32}$');
