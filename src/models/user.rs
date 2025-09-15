use std::collections::HashMap;

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sqlx::{Type, types::Json};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    #[default]
    Online,
    Idle,
    Dnd,
    Invisible,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserTwoFactorRecoveryCode {
    pub code: String,
    pub used_at: Option<DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNotification {
    pub r#type: u8,
    pub target_id: i64,
    pub read: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSettings {
    pub theme: Option<String>,
    pub locale: Option<String>,
    pub developer_mode: Option<bool>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub description: Option<String>,
    pub custom_status: Option<String>,
    pub status: UserStatus,
    pub avatar: Option<String>,
    pub banner: Option<String>,
    pub banner_color: i32,
    pub accent_color: Option<i32>,
    pub password_hash: String,
    pub password_reset_token: Option<String>,
    pub password_reset_expires: Option<DateTime<chrono::Utc>>,
    pub two_factor_secret: Option<String>,
    pub recovery_codes: Option<Json<Vec<UserTwoFactorRecoveryCode>>>,
    pub two_factor_temp_secret: Option<String>,
    pub email: Option<String>,
    pub email_verification_token: Option<String>,
    pub email_verification_code: Option<String>,
    pub phone: Option<String>,
    pub phone_verification_code: Option<String>,
    pub phone_verification_expires: Option<DateTime<chrono::Utc>>,
    pub system: bool,
    #[sqlx(default)]
    pub notes: Json<HashMap<i64, String>>,
    #[sqlx(default)]
    pub notifications: Json<Vec<UserNotification>>,
    #[sqlx(default)]
    pub settings: Json<UserSettings>,
    pub created_at: DateTime<chrono::Utc>,
    pub is_deleted: bool,
}
