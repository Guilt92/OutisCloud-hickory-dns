-- Migration 005: idempotency key store for safe retries of mutating API calls.
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT NOT NULL,
    user_id UUID NOT NULL,
    endpoint TEXT NOT NULL,
    status INT NOT NULL DEFAULT 200,
    response JSONB,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (key, user_id, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires_at ON idempotency_keys(expires_at);
