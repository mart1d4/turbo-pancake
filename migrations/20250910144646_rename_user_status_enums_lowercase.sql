-- Add migration script here
ALTER TYPE user_status RENAME VALUE 'ONLINE' TO 'online';
ALTER TYPE user_status RENAME VALUE 'IDLE' TO 'idle';
ALTER TYPE user_status RENAME VALUE 'DO_NOT_DISTURB' TO 'dnd';
ALTER TYPE user_status RENAME VALUE 'INVISIBLE' TO 'invisible';
ALTER TYPE user_status RENAME VALUE 'OFFLINE' TO 'offline';
