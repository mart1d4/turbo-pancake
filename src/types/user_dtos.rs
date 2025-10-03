use crate::models::user::{User, UserStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicUser {
    #[serde(with = "serde_str")]
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
    pub email: Option<String>,
    pub phone: Option<String>,
    pub system: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for PublicUser {
    fn from(user: User) -> Self {
        PublicUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            description: user.description,
            custom_status: user.custom_status,
            status: user.status,
            avatar: user.avatar,
            banner: user.banner,
            banner_color: user.banner_color,
            accent_color: user.accent_color,
            email: user.email,
            phone: user.phone,
            system: user.system,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorRecoveryCode {
    pub code: String,
    pub used: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginUser {
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
    pub two_factor_secret: Option<String>,
    pub two_factor_recovery_codes: Option<Json<Vec<TwoFactorRecoveryCode>>>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub system: bool,
    pub created_at: DateTime<Utc>,
    pub is_deleted: bool,
}

impl From<LoginUser> for PublicUser {
    fn from(user: LoginUser) -> Self {
        PublicUser {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            description: user.description,
            custom_status: user.custom_status,
            status: user.status,
            avatar: user.avatar,
            banner: user.banner,
            banner_color: user.banner_color,
            accent_color: user.accent_color,
            email: user.email,
            phone: user.phone,
            system: user.system,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SetupTwoFactorUser {
    pub password_hash: String,
    pub two_factor_secret: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConfirmTwoFactorUser {
    pub two_factor_secret: Option<String>,
    pub two_factor_temp_secret: Option<String>,
}
