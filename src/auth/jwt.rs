use axum::{
    RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Validation, decode};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::{errors::AppError, state::AppState};

pub const ACCESS_TOKEN_EXPIRATION_SECONDS: i64 = 15 * 60; // 15 minutes
pub const REFRESH_TOKEN_EXPIRATION_DAYS: i64 = 30; // 30 days

// Initialize JWT Keys statically
pub static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

pub struct Keys {
    pub encoding: EncodingKey,
    pub decoding: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

// --- Access Token Claims ---
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: i64,
    pub exp: usize,
    pub iat: usize,
}

// --- Extractor for Authenticated User Data ---
// Used as a parameter in the protected route handlers
pub struct AuthorizedUser {
    pub id: i64,
    pub username: String,
}
// Why: Represents the result of a successful authentication and user lookup.
// Handlers can directly use `AuthorizedUser { id, username }` in their arguments,
// clearly indicating they need an authenticated user.

#[derive(Debug, sqlx::FromRow)]
struct AuthUserFromDb {
    id: i64,
    username: String,
    is_deleted: bool,
}

impl<S> FromRequestParts<S> for AuthorizedUser
where
    S: Send + Sync,
    AppState: FromRef<S>, // Ensure AppState can be created from the generic state
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // 1. Extract the token from the Authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AppError::InvalidToken)?;

        // 2. Decode the access token claims
        let token_data = decode::<AccessTokenClaims>(
            bearer.token(),
            &KEYS.decoding,
            &Validation::default(), // Validation::default() checks 'exp' automatically
        )
        .map_err(|e| {
            tracing::warn!("Access token decoding failed: {:?}", e); // Log for debugging
            AppError::InvalidToken
        })?;

        // `Validation::default()` already checks this
        if (token_data.claims.exp as i64) < Utc::now().timestamp() {
            return Err(AppError::ExpiredToken);
        }

        // 4. Look up the user in the database to ensure the user still exists and is active.
        // This is crucial for security (e.g., if a user was deleted, banned, or their access revoked)
        let user = sqlx::query_as!(
            AuthUserFromDb,
            r#"
            SELECT id, username, is_deleted
            FROM users
            WHERE id = $1
            "#,
            token_data.claims.sub
        )
        .fetch_optional(&app_state.db) // Use app_state.db for the pool
        .await? // Use `?` operator which now converts `sqlx::Error` into `AppError::DatabaseError`
        .ok_or(AppError::InvalidToken)?; // User associated with token not found/deleted

        Ok(AuthorizedUser {
            id: user.id,
            username: user.username,
        })
    }
}
