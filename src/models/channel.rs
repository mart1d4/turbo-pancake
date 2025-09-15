use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)] // Make this enum an i32 for database storage
pub enum ChannelType {
    GuildText = 0,
    DM = 1,
    GuildVoice = 2,
    GroupDM = 3,
    GuildCategory = 4,
    GuildAnnouncement = 5,
    PublicThread = 11,
    PrivateThread = 12,
    GuildStageVoice = 13,
    GuildForum = 15,
    GuildMedia = 16,
}

// implement from/tryfrom for i32 for seamless conversion between db and rust
impl From<ChannelType> for i32 {
    fn from(ct: ChannelType) -> Self {
        ct as i32
    }
}

impl TryFrom<i32> for ChannelType {
    type Error = String;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ChannelType::GuildText),
            1 => Ok(ChannelType::DM),
            2 => Ok(ChannelType::GuildVoice),
            3 => Ok(ChannelType::GroupDM),
            4 => Ok(ChannelType::GuildCategory),
            5 => Ok(ChannelType::GuildAnnouncement),
            11 => Ok(ChannelType::PublicThread),
            12 => Ok(ChannelType::PrivateThread),
            13 => Ok(ChannelType::GuildStageVoice),
            15 => Ok(ChannelType::GuildForum),
            16 => Ok(ChannelType::GuildMedia),
            _ => Err(format!("Unknown channel type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)] // Make this enum an u8
pub enum PermissionOverwriteType {
    Role = 0,
    UserId = 1,
}

// implement from/tryfrom for i8 for seamless conversion between db and rust
impl From<PermissionOverwriteType> for i8 {
    fn from(ct: PermissionOverwriteType) -> Self {
        ct as i8
    }
}

impl TryFrom<i8> for PermissionOverwriteType {
    type Error = String;
    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PermissionOverwriteType::Role),
            1 => Ok(PermissionOverwriteType::UserId),
            _ => Err(format!("Unknown permission overwrite type: {}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionOverwrite {
    pub id: i64,
    pub r#type: PermissionOverwriteType,
    pub allow: i64,
    pub deny: i64,
}

// --- Channel Model Struct ---
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct Channel {
    pub id: i64,
    pub r#type: ChannelType, // Using `r#type` because `type` is a Rust keyword
    pub name: Option<String>,
    pub topic: Option<String>,
    pub icon: Option<String>,
    pub nsfw: Option<bool>,
    pub position: Option<i32>, // INT maps to i32
    pub parent_id: Option<i64>,
    pub last_message_id: Option<i64>,
    pub last_pin_timestamp: Option<DateTime<chrono::Utc>>,
    pub bitrate: Option<i32>,
    pub rate_limit: Option<i32>,
    pub user_limit: Option<i32>,
    pub rtc_region: Option<String>,
    pub video_quality_mode: Option<String>,
    pub owner_id: Option<i64>,
    pub guild_id: Option<i64>,
    pub permission_overwrites: Json<Vec<PermissionOverwrite>>,
    pub created_at: DateTime<chrono::Utc>,
    pub updated_at: DateTime<chrono::Utc>,
    pub is_deleted: bool,
}
