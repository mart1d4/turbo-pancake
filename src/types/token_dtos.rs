use chrono::DateTime;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct RefreshTokenSelect {
    pub id: i64,
    pub user_id: i64,
    pub expires: DateTime<chrono::Utc>,
}
