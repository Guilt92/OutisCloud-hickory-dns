-- Migration 006: platform automation, bulk operations and extended zone lifecycle.
-- Mirrors the DDL in crates/control_api/src/{automation,zone_ops}.rs.

-- Extended lifecycle state (ADR-0006 + hold/archive extension)
ALTER TABLE zones ADD COLUMN IF NOT EXISTS hold_reason TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS hold_until TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS verified_via TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ;

-- Scoped personal API tokens (only the SHA-256 hash is stored)
CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    prefix TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

-- Durable async jobs (bulk import, exports, ...)
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    progress INT NOT NULL DEFAULT 0,
    total INT NOT NULL DEFAULT 0,
    input JSONB,
    result JSONB,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jobs_user_created ON jobs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

-- Signed webhooks with retry/dead-letter handling
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT now(),
    response_status INT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending ON webhook_deliveries(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);

-- Active health monitors (SSRF-safe target validation is enforced in the API)
CREATE TABLE IF NOT EXISTS health_checks (
    id UUID PRIMARY KEY,
    zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    record_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    target TEXT NOT NULL,
    port INT NOT NULL DEFAULT 53,
    interval_secs INT NOT NULL DEFAULT 30,
    timeout_ms INT NOT NULL DEFAULT 3000,
    failure_threshold INT NOT NULL DEFAULT 3,
    success_threshold INT NOT NULL DEFAULT 2,
    enabled BOOLEAN NOT NULL DEFAULT true,
    status TEXT NOT NULL DEFAULT 'unknown',
    consecutive_failures INT NOT NULL DEFAULT 0,
    consecutive_successes INT NOT NULL DEFAULT 0,
    last_checked_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_health_checks_zone ON health_checks(zone_id);
CREATE TABLE IF NOT EXISTS health_check_results (
    id UUID PRIMARY KEY,
    check_id UUID NOT NULL REFERENCES health_checks(id) ON DELETE CASCADE,
    ok BOOLEAN NOT NULL,
    latency_ms INT,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_health_check_results_check ON health_check_results(check_id, created_at DESC);

-- Secondary zone refresh state and TSIG keys for authenticated transfers
ALTER TABLE zones ADD COLUMN IF NOT EXISTS primary_addr TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_at TIMESTAMPTZ;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_serial BIGINT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS last_transfer_error TEXT;
ALTER TABLE zones ADD COLUMN IF NOT EXISTS transfer_serial BIGINT;
CREATE TABLE IF NOT EXISTS tsig_keys (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
    secret TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    rotated_at TIMESTAMPTZ
);
