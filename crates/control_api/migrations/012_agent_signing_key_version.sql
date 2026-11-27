-- Existing agents retain their JWT-derived verification key until an operator
-- rotates their token and installs the returned independent signing key.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS signing_key_version SMALLINT NOT NULL DEFAULT 1;
