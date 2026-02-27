-- Migration 002: Add missing fields and nameservers table
-- Adds fields required by the API and creates nameservers configuration table

-- Add missing fields to zones table
ALTER TABLE zones ADD COLUMN IF NOT EXISTS geodns_enabled BOOLEAN DEFAULT true;

-- Add missing fields to servers table  
ALTER TABLE servers ADD COLUMN IF NOT EXISTS port INT DEFAULT 53;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS enabled BOOLEAN DEFAULT true;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS dnssec BOOLEAN DEFAULT false;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS enable_logging BOOLEAN DEFAULT true;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS max_cache_ttl INT DEFAULT 3600;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS min_cache_ttl INT DEFAULT 60;

-- Create nameservers table for authoritative nameserver configuration
-- This stores the NS records that will be used for all zones
CREATE TABLE IF NOT EXISTS nameservers (
    id UUID PRIMARY KEY,
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    glue_ip TEXT,
    sort_order INT DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(hostname)
);

CREATE INDEX IF NOT EXISTS idx_nameservers_enabled ON nameservers(enabled);
CREATE INDEX IF NOT EXISTS idx_nameservers_sort_order ON nameservers(sort_order);

-- Insert default nameservers if none exist
INSERT INTO nameservers (id, hostname, ip_address, sort_order, enabled)
SELECT '11111111-1111-1111-1111-111111111111'::uuid, 'ns1.my-dns.com', '192.0.2.1', 1, true
WHERE NOT EXISTS (SELECT 1 FROM nameservers);

INSERT INTO nameservers (id, hostname, ip_address, sort_order, enabled)
SELECT '22222222-2222-2222-2222-222222222222'::uuid, 'ns2.my-dns.com', '192.0.2.2', 2, true
WHERE NOT EXISTS (SELECT 1 FROM nameservers);
