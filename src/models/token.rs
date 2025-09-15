use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct UserToken {
    pub id: i64, // Snowflake ID for the refresh token entry
    pub user_id: i64,
    pub token: String, // The actual refresh token string
    pub expires: DateTime<chrono::Utc>,
    pub user_agent: Option<String>,
    pub ip: Option<IpAddr>, // `std::net::IpAddr` maps to PostgreSQL `INET`
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub created_at: DateTime<chrono::Utc>,
}
