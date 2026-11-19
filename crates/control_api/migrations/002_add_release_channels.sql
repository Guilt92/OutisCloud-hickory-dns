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

-- agent_health_history and the legacy rate_limits table were removed: both
-- were migration-only objects with no application references, and the latter
-- collided with the live rate_limits table created by migrate_db().
