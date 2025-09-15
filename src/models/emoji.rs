use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Emoji {
    pub id: i64,
    pub name: String,
    pub url: String,
    pub animated: bool,
    pub guild_id: i64,
    pub created_at: DateTime<chrono::Utc>,
}
