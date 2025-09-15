use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct Blocked {
    pub blocker_id: i64,
    pub blocked_id: i64,
}
