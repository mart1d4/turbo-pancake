use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct MessageReaction {
    pub message_id: i64,
    pub emoji_id: Option<i64>,      // NULL for default/unicode emojis
    pub emoji_name: Option<String>, // Store name for default/unicode emojis
    pub user_id: i64,
}
