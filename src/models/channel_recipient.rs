use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct ChannelRecipient {
    pub channel_id: i64,
    pub user_id: i64,
    pub is_hidden: bool,
}
