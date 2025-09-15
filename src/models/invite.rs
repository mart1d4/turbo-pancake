use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Invite {
    pub id: i64,
    pub code: String,
    pub uses: i32, // INT NOT NULL DEFAULT '0'
    pub temporary: bool,
    pub max_age: i32,  // INT NOT NULL DEFAULT '86400'
    pub max_uses: i32, // INT NOT NULL DEFAULT '100'
    pub inviter_id: i64,
    pub channel_id: i64,
    pub guild_id: Option<i64>, // NULLable FK
    pub expires_at: DateTime<chrono::Utc>,
    pub created_at: DateTime<chrono::Utc>,
}
