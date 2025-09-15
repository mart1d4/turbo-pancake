-- Add migration script here

ALTER TABLE guild_logs DROP COLUMN guild_id RESTRICT;
ALTER TABLE guild_logs ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE guild_logs RENAME COLUMN action TO action_type;
ALTER TABLE guild_logs ADD COLUMN reason VARCHAR(512);
--DROP INDEX idx_logs_guild;
