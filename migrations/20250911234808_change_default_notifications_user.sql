-- Add migration script here
ALTER TABLE users ALTER COLUMN notifications DROP DEFAULT;

UPDATE users SET notifications = '[]'::jsonb WHERE notifications = '{}'::jsonb;

ALTER TABLE users ALTER COLUMN notifications SET DEFAULT '[]'::jsonb;
