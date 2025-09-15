use axum::{
    Json,
    extract::{OriginalUri, State},
    http::HeaderMap,
};
use axum_extra::extract::WithRejection;
use bcrypt::{DEFAULT_COST, hash, verify};
use chrono::Utc;
use headers::{HeaderMapExt, UserAgent};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::{
        ACCESS_TOKEN_EXPIRATION_SECONDS, AccessTokenClaims, AuthResponse, KEYS, LoginPayload,
        REFRESH_TOKEN_EXPIRATION_DAYS, RefreshResponse, RefreshTokenPayload, RegisterPayload,
        generate_id,
    },
    errors::AppError,
    types::{LoginUser, PublicUser, RefreshTokenSelect},
};

// Helper function to get client IP address from request headers or socket address
fn get_client_ip(headers: &HeaderMap, _original_uri: &OriginalUri) -> Option<std::net::IpAddr> {
    // Check common proxy headers first (X-Forwarded-For, X-Real-IP)
    if let Some(x_forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(s) = x_forwarded_for.to_str() {
            if let Some(ip_str) = s.split(',').next() {
                // Take the first IP in the list
                if let Ok(ip) = ip_str.trim().parse() {
                    return Some(ip);
                }
            }
        }
    }
    if let Some(x_real_ip) = headers.get("X-Real-IP") {
        if let Ok(s) = x_real_ip.to_str() {
            if let Ok(ip) = s.parse() {
                return Some(ip);
            }
        }
    }

    // In a real Axum app, you'd extract `axum::extract::ConnectInfo<std::net::SocketAddr>`
    // which provides the peer IP. For simplicity here, relying on headers if available.
    // If you need the direct peer IP, that would be an additional extractor in the handler.
    // For this example, let's keep it simple with headers.
    None
}

async fn create_tokens(
    pool: &PgPool,
    user_id: i64,
    headers: &HeaderMap,
    original_uri: &OriginalUri,
) -> Result<(String, String, usize), AppError> {
    let access_token_exp = Utc::now() + chrono::Duration::seconds(ACCESS_TOKEN_EXPIRATION_SECONDS);
    let access_token_claims = AccessTokenClaims {
        sub: user_id,
        exp: access_token_exp.timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
    };
    let access_token_jwt = jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &access_token_claims,
        &KEYS.encoding,
    )
    .map_err(|_| AppError::TokenCreation)?;

    let refresh_token_db_string = base64_url::encode(&Uuid::new_v4().as_bytes()); // Generate a random string
    let refresh_token_exp = Utc::now() + chrono::Duration::days(REFRESH_TOKEN_EXPIRATION_DAYS);

    // Derive client info
    let user_agent = headers.typed_get::<UserAgent>().map(|ua| ua.to_string());
    let ip = get_client_ip(headers, original_uri);
    // For now, these remain None or placeholder
    let country: Option<String> = None;
    let region: Option<String> = None;
    let city: Option<String> = None;

    let token_id = generate_id();
    sqlx::query!(
        r#"
        INSERT INTO user_tokens (id, user_id, token, expires, user_agent, ip, country, region, city, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
        token_id,
        user_id,
        refresh_token_db_string,
        refresh_token_exp,
        user_agent,
        ip as _,
        country,
        region,
        city,
        Utc::now()
    )
    .execute(pool)
    .await?;

    Ok((
        access_token_jwt,
        refresh_token_db_string,
        ACCESS_TOKEN_EXPIRATION_SECONDS as usize,
    ))
}

pub async fn register(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    original_uri: OriginalUri,
    WithRejection(Json(payload), _): WithRejection<Json<RegisterPayload>, AppError>,
) -> Result<Json<AuthResponse>, AppError> {
    let existing_user_by_username = sqlx::query!(
        r#"SELECT id FROM users WHERE username = $1"#,
        payload.username
    )
    .fetch_optional(&pool)
    .await?;

    if existing_user_by_username.is_some() {
        return Err(AppError::UserAlreadyExists);
    }

    let hashed_password = hash(&payload.password, DEFAULT_COST)?;
    let user_id = generate_id();

    let user = sqlx::query_as!(
        PublicUser,
        r#"
        INSERT INTO users (
            id, username, display_name, password_hash, banner_color
        )
        VALUES (
            $1, $2, $3, $4, $5
        )
        RETURNING
            id, username, display_name, description, custom_status,
            status as "status!: _", avatar, banner, banner_color,
            accent_color, email, phone, system, created_at
        "#,
        user_id,
        payload.username,
        payload.username,
        hashed_password,
        0
    )
    .fetch_one(&pool)
    .await?;

    let (access_token, refresh_token, expires_in) =
        create_tokens(&pool, user.id, &headers, &original_uri).await?;

    Ok(Json(AuthResponse {
        access_token: access_token,
        refresh_token: refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
        user: user,
    }))
}

pub async fn login(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    original_uri: OriginalUri,
    Json(payload): Json<LoginPayload>,
    //body_bytes: Bytes,
) -> Result<Json<AuthResponse>, AppError> {
    //let payload: LoginPayload =
    //serde_json::from_slice(&body_bytes).map_err(|_| AppError::MissingCredentials)?;

    // 1. Find user by username OR email
    let user = sqlx::query_as!(
        LoginUser,
        r#"
        SELECT
            id, username, display_name, description, custom_status,
            status as "status!: _", avatar, banner, banner_color,
            accent_color, email, phone, system, created_at, password_hash, is_deleted
        FROM users
        WHERE username = $1 OR email = $1
        "#,
        payload.identifier
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::WrongCredentials)?;

    // 2. Verify password
    let passwords_match = verify(&payload.password, &user.password_hash)?;
    if !passwords_match {
        return Err(AppError::WrongCredentials);
    }

    // 3. Generate and store Refresh Token
    let (access_token_jwt, refresh_token_db_string, expires_in) =
        create_tokens(&pool, user.id, &headers, &original_uri).await?;

    Ok(Json(AuthResponse {
        access_token: access_token_jwt,
        refresh_token: refresh_token_db_string,
        token_type: "Bearer".to_string(),
        expires_in,
        user: PublicUser::from(user),
    }))
}

pub async fn refresh_token(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    original_uri: OriginalUri,
    Json(payload): Json<RefreshTokenPayload>,
) -> Result<Json<RefreshResponse>, AppError> {
    let user_token = sqlx::query_as!(
        RefreshTokenSelect,
        r#"SELECT id, user_id, expires FROM user_tokens WHERE token = $1"#,
        payload.refresh_token
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::InvalidToken)?;

    // Check if refresh token has expired
    if user_token.expires < Utc::now() {
        // Also clean up the expired token immediately
        sqlx::query!("DELETE FROM user_tokens WHERE id = $1", user_token.id)
            .execute(&pool)
            .await
            .ok(); // Log error but don't fail refresh request if delete fails
        return Err(AppError::ExpiredToken);
    }

    let (new_access_token, new_refresh_token, expires_in) =
        create_tokens(&pool, user_token.user_id, &headers, &original_uri).await?;

    // Invalidate the old refresh token
    sqlx::query!("DELETE FROM user_tokens WHERE id = $1", user_token.id)
        .execute(&pool)
        .await?;

    Ok(Json(RefreshResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
    }))
}
