-- Add migration script here
ALTER TABLE users ALTER COLUMN status SET DEFAULT 'online';
