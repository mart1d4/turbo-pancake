use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberProfile {
    pub nick: Option<String>,
    pub roles: Vec<i64>,
    pub joined_at: DateTime<chrono::Utc>,
    pub deaf: bool,
    pub mute: bool,
    pub communication_disabled_until: Option<DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, FromRow)]
pub struct GuildMember {
    pub guild_id: i64,
    pub user_id: i64,
    pub profile: Json<MemberProfile>,
}
