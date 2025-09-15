use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeScreen {
    pub description: Option<String>,
    pub welcome_channels: Vec<WelcomeChannel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeChannel {
    pub channel_id: i64,
    pub description: String,
    pub emoji_id: Option<i64>,
    pub emoji_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum VerificationLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    VeryHigh = 4,
}

// Implement From/TryFrom for i32 for seamless conversion between DB and Rust
impl From<VerificationLevel> for i32 {
    fn from(ct: VerificationLevel) -> Self {
        ct as i32
    }
}

impl TryFrom<i32> for VerificationLevel {
    type Error = String;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(VerificationLevel::None),
            1 => Ok(VerificationLevel::Low),
            2 => Ok(VerificationLevel::Medium),
            3 => Ok(VerificationLevel::High),
            4 => Ok(VerificationLevel::VeryHigh),
            _ => Err(format!("Unknown verification level: {}", value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct Guild {
    pub id: i64,
    pub name: String,
    pub icon: Option<String>,
    pub banner: Option<String>,
    pub splash: Option<String>,
    pub description: Option<String>,
    pub system_channel_id: Option<i64>,
    pub rules_channel_id: Option<i64>,
    pub send_welcome_messages: bool,
    pub notify_everyone: bool,
    pub afk_channel_id: Option<i64>,
    pub afk_timeout: Option<i32>,
    pub vanity_url_code: Option<String>,
    pub vanity_url_uses: Option<i32>,
    pub welcome_screen: Json<Option<WelcomeScreen>>,
    pub discoverable: bool,
    pub verification_level: VerificationLevel,
    pub mfa_enabled: bool,
    pub owner_id: i64,
    pub created_at: DateTime<chrono::Utc>,
    pub is_deleted: bool,
}
