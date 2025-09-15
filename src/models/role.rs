use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub color: Option<i32>,
    pub hoist: bool,
    pub position: i32, // INT NOT NULL
    pub everyone: bool,
    pub permissions: i64, // BIGINT NOT NULL for bitmask
    pub mentionable: bool,
    pub guild_id: i64,
    pub created_at: DateTime<chrono::Utc>,
}
