-- Migration 002: Add release channels and config versioning

-- Add release_channel column if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agent_configs' AND column_name = 'release_channel') THEN
        ALTER TABLE agent_configs ADD COLUMN release_channel TEXT NOT NULL DEFAULT 'stable';
    END IF;
END $$;

-- Add config_version column if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agent_configs' AND column_name = 'config_version') THEN
        ALTER TABLE agent_configs ADD COLUMN config_version INT NOT NULL DEFAULT 1;
    END IF;
END $$;

-- Add is_active column if not exists
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'agent_configs' AND column_name = 'is_active') THEN
        ALTER TABLE agent_configs ADD COLUMN is_active BOOLEAN DEFAULT false;
    END IF;
END $$;

-- Add health check history table
CREATE TABLE IF NOT EXISTS agent_health_history (
    id UUID PRIMARY KEY,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    cpu_usage FLOAT,
    memory_usage FLOAT,
    disk_usage FLOAT,
    query_count BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    recorded_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_health_history_agent_id ON agent_health_history(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_health_history_recorded_at ON agent_health_history(recorded_at);

-- Add API rate limiting table
CREATE TABLE IF NOT EXISTS rate_limits (
    id UUID PRIMARY KEY,
    ip_address TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    request_count INT DEFAULT 0,
    window_start TIMESTAMPTZ DEFAULT now(),
    window_duration INT DEFAULT 60,
    blocked_until TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_endpoint ON rate_limits(ip_address, endpoint);
CREATE INDEX IF NOT EXISTS idx_rate_limits_blocked ON rate_limits(blocked_until) WHERE blocked_until IS NOT NULL;
