-- Add migration script here

CREATE TABLE login_challenges (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE users ADD COLUMN two_factor_temp_expires TIMESTAMPTZ NULL;
ALTER TABLE users RENAME COLUMN recovery_codes TO two_factor_recovery_codes;
ALTER TABLE users ADD COLUMN email_verification_expires TIMESTAMPTZ NULL;
