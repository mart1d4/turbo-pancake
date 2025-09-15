use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct GuildBan {
    pub guild_id: i64,
    pub user_id: i64,
    pub reason: Option<String>,
    pub banned_at: DateTime<chrono::Utc>,
    pub banned_by_id: Option<i64>,
}
