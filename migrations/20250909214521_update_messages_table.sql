-- Add migration script here
ALTER TABLE messages ADD COLUMN components JSONB;
ALTER TABLE messages ADD COLUMN poll JSONB;
ALTER TABLE messages ADD COLUMN call JSONB;
ALTER TABLE messages ADD COLUMN webhook_id BIGINT;
ALTER TABLE messages ADD COLUMN nonce VARCHAR(256);
