-- Add migration script here
ALTER TABLE guilds RENAME COLUMN notify_everyone TO notify_for_all_messages;
