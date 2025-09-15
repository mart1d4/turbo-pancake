-- Add migration script here

-- Custom Type for User Status
CREATE TYPE user_status AS ENUM ('ONLINE', 'IDLE', 'DO_NOT_DISTURB', 'INVISIBLE', 'OFFLINE');

-- User Table
CREATE TABLE users (
    id BIGINT PRIMARY KEY,

    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,

    description VARCHAR(255) NULL,
    custom_status VARCHAR(255) NULL,
    status user_status NOT NULL DEFAULT 'ONLINE',

    avatar VARCHAR(255) NULL,
    banner VARCHAR(255) NULL,

    banner_color VARCHAR(7) NOT NULL,
    accent_color VARCHAR(7) NULL,

    password_hash VARCHAR(255) NOT NULL,
    password_reset_token VARCHAR(255) NULL,
    password_reset_expires TIMESTAMPTZ NULL,

    two_factor_secret VARCHAR(255) NULL,
    recovery_codes JSONB NULL,
    two_factor_temp_secret VARCHAR(255) NULL,

    email VARCHAR(255) UNIQUE,
    email_verification_token TEXT,
    email_verification_code VARCHAR(6),

    phone VARCHAR(15) UNIQUE,
    phone_verification_code VARCHAR(255),
    phone_verification_expires TIMESTAMPTZ NULL,

    system BOOLEAN NOT NULL DEFAULT FALSE,

    notes JSONB NOT NULL DEFAULT '{}'::jsonb,
    notifications JSONB NOT NULL DEFAULT '{}'::jsonb,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX users_is_deleted_idx ON users (is_deleted);


-- User Tokens Table (Refresh Tokens)
CREATE TABLE user_tokens (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token VARCHAR(512) NOT NULL UNIQUE,
    expires TIMESTAMPTZ NOT NULL,
    user_agent TEXT NULL,
    ip INET NULL,
    country VARCHAR(255) NULL,
    region VARCHAR(255) NULL,
    city VARCHAR(255) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_tokens_user_id ON user_tokens (user_id);
-- No need for idx_user_tokens_token as UNIQUE creates an index


-- Channels Table
-- Function to update updated_at timestamp automatically (for ON UPDATE CURRENT_TIMESTAMP)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TYPE channel_quality_mode AS ENUM ('AUTO', 'FULL');

CREATE TABLE channels (
    id BIGINT PRIMARY KEY,
    type INT NOT NULL,

    name VARCHAR(255),
    topic VARCHAR(1024),
    icon VARCHAR(255),
    nsfw BOOLEAN,

    position INT,
    parent_id BIGINT NULL REFERENCES channels(id),

    last_message_id BIGINT NULL,
    last_pin_timestamp TIMESTAMPTZ,

    bitrate INT,
    rate_limit INT,
    user_limit INT,
    rtc_region VARCHAR(255),
    video_quality_mode channel_quality_mode,

    owner_id BIGINT NULL REFERENCES users(id),
    guild_id BIGINT NULL,

    permission_overwrites JSONB NOT NULL DEFAULT '[]'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX channels_parent_id_idx ON channels (parent_id);
CREATE INDEX channels_guild_id_idx ON channels (guild_id);
CREATE INDEX channels_owner_id_idx ON channels (owner_id);
CREATE INDEX channels_last_message_id_idx ON channels (last_message_id);
CREATE INDEX channels_last_pin_timestamp_idx ON channels (last_pin_timestamp);
CREATE INDEX channels_type_idx ON channels (type);
CREATE INDEX channels_position_idx ON channels (position);
CREATE INDEX channels_is_deleted_idx ON channels (is_deleted);

-- Trigger for updated_at
CREATE TRIGGER update_channels_updated_at
BEFORE UPDATE ON channels
FOR EACH ROW
EXECUTE PROCEDURE update_updated_at_column();


-- Guilds Table
CREATE TABLE guilds (
    id BIGINT PRIMARY KEY,

    name VARCHAR(255) NOT NULL,
    icon VARCHAR(255),
    banner VARCHAR(255),
    description VARCHAR(255),

    system_channel_id BIGINT NULL REFERENCES channels(id) ON DELETE SET NULL,

    send_welcome_messages BOOLEAN NOT NULL DEFAULT TRUE,
    notify_everyone BOOLEAN NOT NULL DEFAULT TRUE,

    afk_channel_id BIGINT NULL REFERENCES channels(id) ON DELETE SET NULL,
    afk_timeout INT, -- In seconds

    vanity_url VARCHAR(255) UNIQUE,
    vanity_url_uses INT,
    welcome_screen JSONB,
    discoverable BOOLEAN NOT NULL DEFAULT FALSE,

    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX guilds_owner_id_idx ON guilds (owner_id);
CREATE INDEX guilds_is_deleted_idx ON guilds (is_deleted);

-- Add Guild_id Foreign Key to Channels AFTER Guilds table is created
ALTER TABLE channels
ADD CONSTRAINT fk_channels_guild_id
FOREIGN KEY (guild_id) REFERENCES guilds(id);


-- Messages Table
CREATE TABLE messages (
    id BIGINT PRIMARY KEY,
    type INT NOT NULL,

    content TEXT,
    attachments JSONB NOT NULL DEFAULT '[]'::jsonb,
    embeds JSONB NOT NULL DEFAULT '[]'::jsonb,

    edited TIMESTAMPTZ,
    pinned TIMESTAMPTZ,

    reference_id BIGINT NULL REFERENCES messages(id),
    mention_everyone BOOLEAN NOT NULL DEFAULT FALSE,

    author_id BIGINT NOT NULL REFERENCES users(id),
    channel_id BIGINT NOT NULL REFERENCES channels(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX messages_author_id_idx ON messages (author_id);
CREATE INDEX messages_channel_id_idx ON messages (channel_id);
CREATE INDEX messages_reference_id_idx ON messages (reference_id);
CREATE INDEX messages_type_idx ON messages (type);
CREATE INDEX messages_created_at_idx ON messages (created_at);
CREATE INDEX messages_pinned_idx ON messages (pinned);


-- Emojis Table
CREATE TABLE emojis (
    id BIGINT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(255) NOT NULL,
    animated BOOLEAN NOT NULL DEFAULT FALSE,
    guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX emojis_guild_id_idx ON emojis (guild_id);


-- Roles Table
CREATE TABLE roles (
    id BIGINT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    color VARCHAR(7),
    hoist BOOLEAN NOT NULL DEFAULT FALSE,
    position INT NOT NULL,
    everyone BOOLEAN NOT NULL DEFAULT FALSE,
    permissions BIGINT NOT NULL, -- Store as BIGINT for bitmask
    mentionable BOOLEAN NOT NULL DEFAULT FALSE,
    guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX roles_guild_id_idx ON roles (guild_id);
CREATE INDEX roles_position_idx ON roles (position);


-- Invites Table
CREATE TABLE invites (
    id BIGINT PRIMARY KEY,
    code VARCHAR(8) NOT NULL UNIQUE,
    uses INT NOT NULL DEFAULT 0,
    temporary BOOLEAN NOT NULL DEFAULT FALSE,
    max_age INT NOT NULL DEFAULT 86400, -- In seconds
    max_uses INT NOT NULL DEFAULT 100,
    inviter_id BIGINT NOT NULL REFERENCES users(id),
    channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    guild_id BIGINT NULL REFERENCES guilds(id) ON DELETE CASCADE, -- Invites can be for DMs (no guild)
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX invites_inviter_id_idx ON invites (inviter_id);
CREATE INDEX invites_channel_id_idx ON invites (channel_id);
CREATE INDEX invites_guild_id_idx ON invites (guild_id);
CREATE INDEX invites_expires_at_idx ON invites (expires_at);
CREATE INDEX invites_created_at_idx ON invites (created_at);


-- Friends Table (Many-to-Many relationship)
CREATE TABLE friends (
    a_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Renamed from 'A' to avoid keywords
    b_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Renamed from 'B'

    -- Ensures (u1, u2) is unique and (u2, u1) is also considered the same unique pair
    -- This requires checking application-side to ensure you insert (MIN(id1, id2), MAX(id1, id2))
    -- Or, use two separate unique indexes as you had in MySQL if you don't enforce min/max order
    PRIMARY KEY (a_id, b_id), -- Composite primary key
    CHECK (a_id < b_id) -- Enforce canonical ordering to avoid duplicate friendships
);

CREATE INDEX idx_friends_a ON friends (a_id);
CREATE INDEX idx_friends_b ON friends (b_id);


-- Blocked Table
CREATE TABLE blocked (
    blocker_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    PRIMARY KEY (blocker_id, blocked_id) -- A user can block another user only once
);

CREATE INDEX idx_blocked_blocker ON blocked (blocker_id);
CREATE INDEX idx_blocked_blocked ON blocked (blocked_id);


-- Requests Table (Friend Requests)
CREATE TABLE requests (
    requester_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    PRIMARY KEY (requester_id, requested_id), -- A user can send a request to another user only once
    CHECK (requester_id <> requested_id) -- A user cannot send a request to themselves
);

CREATE INDEX idx_requests_requester ON requests (requester_id);
CREATE INDEX idx_requests_requested ON requests (requested_id);


-- ChannelRecipients (for DMs, Group DMs)
CREATE TABLE channel_recipients (
    channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_hidden BOOLEAN NOT NULL DEFAULT FALSE,

    PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX idx_recipients_channel ON channel_recipients (channel_id);
CREATE INDEX idx_recipients_user ON channel_recipients (user_id);


-- GuildMembers
CREATE TABLE guild_members (
    guild_id BIGINT NOT NULL REFERENCES guilds(id), -- Need to manage than in the app code
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    profile JSONB NOT NULL DEFAULT '{}'::jsonb, -- Store member-specific settings, roles, nickname etc. as JSONB

    PRIMARY KEY (guild_id, user_id) -- A user is a member of a guild only once
);

CREATE INDEX idx_members_user ON guild_members (user_id);


-- Guild Bans
CREATE TABLE guild_bans (
    guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason VARCHAR(1024) NULL, -- Reason for the ban
    banned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the ban occurred
    banned_by_id BIGINT NULL REFERENCES users(id), -- Who banned them

    PRIMARY KEY (guild_id, user_id) -- A user can only be banned once per guild
);

CREATE INDEX idx_bans_user ON guild_bans (user_id);


-- Guild Logs (Audit Log)
-- Note: UNIQUE KEY (`guild_id`, `user_id`, `action`, `created_at`) might be too restrictive if multiple actions happen simultaneously
-- The original MySQL unique key will likely cause issues if multiple similar actions by the same user happen at the exact same millisecond.
-- I'll keep it as a composite index rather than a unique key, as a log should allow duplicates if they happen.
CREATE TABLE guild_logs (
    id BIGINT PRIMARY KEY,
    guild_id BIGINT NOT NULL REFERENCES guilds(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT, -- User performing the action
    target_id BIGINT NULL, -- ID of the entity that was acted upon (user, channel, role etc.)
    action INT NOT NULL, -- Consider an ENUM for audit log actions
    changes JSONB NOT NULL DEFAULT '[]'::jsonb, -- Details of what changed (e.g., old_name, new_name)
    options JSONB NOT NULL DEFAULT '{}'::jsonb, -- Additional options for the action
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_logs_guild ON guild_logs (guild_id);
CREATE INDEX idx_logs_user ON guild_logs (user_id);
CREATE INDEX idx_logs_target ON guild_logs (target_id);
CREATE INDEX idx_logs_action ON guild_logs (action);
CREATE INDEX idx_logs_created_at ON guild_logs (created_at);


-- Message Mentions (User)
CREATE TABLE user_mentions (
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    PRIMARY KEY (message_id, user_id) -- A user is mentioned in a message only once
);

CREATE INDEX idx_mentions_user ON user_mentions (user_id);


-- Message Mentions (Role)
CREATE TABLE role_mentions (
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    PRIMARY KEY (message_id, role_id)
);

CREATE INDEX idx_mentions_role ON role_mentions (role_id);


-- Message Mentions (Channel)
CREATE TABLE channel_mentions (
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    channel_id BIGINT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,

    PRIMARY KEY (message_id, channel_id)
);

CREATE INDEX idx_mentions_channel ON channel_mentions (channel_id);


-- Message Reactions
CREATE TABLE message_reactions (
    message_id BIGINT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    emoji_id BIGINT NULL REFERENCES emojis(id) ON DELETE CASCADE, -- Null for default/unicode emojis
    emoji_name VARCHAR(255) NULL, -- Store name for default/unicode emojis
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    PRIMARY KEY (message_id, user_id, emoji_id, emoji_name) -- User can react once per (message, emoji_id OR emoji_name) combination
    -- The PRIMARY KEY needs to handle the NULL emoji_id case.
    -- For unique, consider a unique index with a partial index for NULLs if needed.
    -- A user can react once per (message, custom_emoji_id) or once per (message, unicode_emoji_name).
    -- This PK will allow one (message, user, emoji_id, NULL) and one (message, user, NULL, emoji_name).
    -- This should work, but test carefully.
);

CREATE INDEX idx_reactions_user ON message_reactions (user_id);
CREATE INDEX idx_reactions_emoji ON message_reactions (emoji_id);
