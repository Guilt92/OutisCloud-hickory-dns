-- Migration 004: Exact-duplicate guard for DNS RRsets
-- Mirrors the invariant enforced by migrate_db() at runtime. A DNS RRset may
-- contain several values, but the same value must not be inserted twice.

ALTER TABLE records DROP CONSTRAINT IF EXISTS records_zone_id_name_record_type_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_records_rrset_value
    ON records(zone_id, lower(name), record_type, value);
