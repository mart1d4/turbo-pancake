use argon2::{
    Argon2, PasswordHash,
    password_hash::{PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use axum::{
    Json,
    extract::{OriginalUri, State},
    http::HeaderMap,
};
use axum_extra::TypedHeader;
use chrono::{Duration, Utc};
use headers::{Authorization, HeaderMapExt, UserAgent, authorization::Bearer};
use rand::{Rng, distr::Alphanumeric, rng};
use resend_rs::{Resend, types::CreateEmailBaseOptions};
use sha1::{Digest, Sha1};
use sqlx::{PgPool, types::Json as SqlxJson};
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use zxcvbn::{Score, zxcvbn};

use crate::{
    auth::{
        ACCESS_TOKEN_EXPIRATION_SECONDS, AccessTokenClaims, AuthResponse, KEYS, LoginPayload,
        REFRESH_TOKEN_EXPIRATION_DAYS, RegisterPayload,
        emails::decode_email_verification_token,
        generate_id, generate_recovery_code_structs, issue_email_verification_token,
        jwt::AuthorizedUser,
        types::{
            ConfirmEmailPayload, ConfirmTwoFactorPayload, ConfirmTwoFactorResponse,
            Disable2FAPayload, LoginResponse, ModifyEmailPayload, SetupTwoFactorPayload,
            SetupTwoFactorResponse, TwoFactorLoginMethod, TwoFactorLoginPayload,
            VerifyPasswordPayload,
        },
    },
    errors::{AppError, Resource},
    extractors::ValidatedJson,
    state::AppState,
    types::{
        LoginUser, PublicUser, RefreshTokenSelect, TwoFactorRecoveryCode,
        user_dtos::{
            ConfirmTwoFactorUser, Disable2FAUser, ModifyEmailUser, SetupTwoFactorUser,
            VerifyPasswordUser,
        },
    },
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

    let refresh_token_db_string = base64_url::encode(&Uuid::new_v4().as_bytes());
    let refresh_token_exp = Utc::now() + Duration::days(REFRESH_TOKEN_EXPIRATION_DAYS);

    // Derive client info
    let user_agent = headers.typed_get::<UserAgent>().map(|ua| ua.to_string());
    let ip = get_client_ip(headers, original_uri);
    // For now, these remain None or placeholder
    let country: Option<String> = None;
    let region: Option<String> = None;
    let city: Option<String> = None;

    println!("IP: {:?}", ip);

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
    ValidatedJson(payload): ValidatedJson<RegisterPayload>,
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

    let estimate = zxcvbn(&payload.password, &[]);
    if estimate.score() <= Score::Two {
        return Err(AppError::PasswordTooWeak);
    }

    let mut hasher = Sha1::new();
    hasher.update(&payload.password.as_bytes());
    let password_sha1_hash = hasher.finalize();
    let full_hex_hash = format!("{:X}", password_sha1_hash);
    let first_five_chars = &full_hex_hash[0..5].to_lowercase();
    let password_hash_tail = &full_hex_hash[5..];

    let hibp_response_body = reqwest::get(format!(
        "https://api.pwnedpasswords.com/range/{}",
        first_five_chars
    ))
    .await?
    .text()
    .await?;

    for line in hibp_response_body.lines() {
        if let Some((hibp_tail, _count)) = line.split_once(':') {
            if hibp_tail == password_hash_tail {
                return Err(AppError::PasswordTooWeak);
            }
        }
    }

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(&payload.password.as_bytes(), &salt)?
        .to_string();
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
        password_hash,
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
    ValidatedJson(payload): ValidatedJson<LoginPayload>,
) -> Result<Json<LoginResponse>, AppError> {
    let user = sqlx::query_as!(
        LoginUser,
        r#"
        SELECT
            id, username, display_name, description, custom_status,
            status as "status!: _", two_factor_recovery_codes as "two_factor_recovery_codes: SqlxJson<Vec<TwoFactorRecoveryCode>>", avatar, banner, banner_color, two_factor_secret,
            accent_color, email, phone, system, created_at, password_hash, is_deleted
        FROM users
        WHERE (username = $1 OR email = $1) AND is_deleted = FALSE
        "#,
        payload.identifier
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::WrongCredentials)?;

    let parsed_hash = PasswordHash::new(&user.password_hash)?;
    let passwords_match =
        Argon2::default().verify_password(&payload.password.as_bytes(), &parsed_hash);

    if !passwords_match.is_ok() {
        return Err(AppError::WrongCredentials);
    }

    if user.two_factor_secret.is_some() {
        let challenge_expires = Utc::now() + Duration::minutes(15);
        let challenge_id = generate_id();

        sqlx::query!(
            r#"
                INSERT INTO login_challenges (id, user_id, created_at, expires_at)
                VALUES ($1, $2, $3, $4)
            "#,
            challenge_id,
            user.id,
            Utc::now(),
            challenge_expires,
        )
        .execute(&pool)
        .await?;

        return Ok(Json(LoginResponse::TwoFactorRequired {
            challenge_id: challenge_id.to_string(),
        }));
    }

    let (access_token_jwt, refresh_token_db_string, expires_in) =
        create_tokens(&pool, user.id, &headers, &original_uri).await?;

    Ok(Json(LoginResponse::Success(AuthResponse {
        access_token: access_token_jwt,
        refresh_token: refresh_token_db_string,
        token_type: "Bearer".to_string(),
        expires_in,
        user: PublicUser::from(user),
    })))
}

pub async fn refresh_token(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    original_uri: OriginalUri,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<AuthResponse>, AppError> {
    let token_string = bearer.token().to_string();

    let user_token = sqlx::query_as!(
        RefreshTokenSelect,
        r#"SELECT id, user_id, expires FROM user_tokens WHERE token = $1"#,
        token_string
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

    let user = sqlx::query_as!(
        PublicUser,
        r#"
        SELECT
            id, username, display_name, description, custom_status,
            status as "status!: _", avatar, banner, banner_color,
            accent_color, email, phone, system, created_at

        FROM users
        WHERE id = $1
        "#,
        user_token.user_id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::ResourceNotFound(Resource::User))?;

    Ok(Json(AuthResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in,
        user: user,
    }))
}

pub async fn check_2fa(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    original_uri: OriginalUri,
    ValidatedJson(payload): ValidatedJson<TwoFactorLoginPayload>,
) -> Result<Json<AuthResponse>, AppError> {
    let user = sqlx::query_as!(
        LoginUser,
        r#"
        SELECT
            u.id, u.username, u.display_name, u.description, u.custom_status,
            u.status as "status!: _", u.avatar, u.banner, u.banner_color,
            u.two_factor_secret, u.two_factor_recovery_codes as "two_factor_recovery_codes: SqlxJson<Vec<TwoFactorRecoveryCode>>", u.accent_color,
            u.email, u.phone, u.system, u.created_at, u.password_hash, u.is_deleted
        FROM users u
        INNER JOIN login_challenges c
            ON c.user_id = u.id
        WHERE c.id = $1
            AND c.expires_at > now()
            AND c.consumed = FALSE
            AND u.is_deleted = FALSE
        "#,
        &payload.challenge_id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::InvalidOrExpiredChallenge)?;

    if user.two_factor_secret.is_none() || user.two_factor_recovery_codes.is_none() {
        return Err(AppError::TwoFactorSecretNotFound);
    }

    match &payload.login_method {
        TwoFactorLoginMethod::Totp(code) => {
            let secret = Secret::Encoded(user.two_factor_secret.clone().unwrap());

            let totp = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret.to_bytes().unwrap(),
                Some("Turbo Pancake".to_string()),
                user.username.clone(),
            )?;

            if !totp.check_current(&code.totp_code).unwrap_or(false) {
                return Err(AppError::InvalidOrExpiredCode);
            }
        }
        TwoFactorLoginMethod::Recovery(code) => {
            if let Some(rc) = user
                .two_factor_recovery_codes
                .clone()
                .unwrap()
                .iter_mut()
                .find(|rc| rc.code == code.recovery_code.to_string())
            {
                if rc.used {
                    return Err(AppError::InvalidOrExpiredCode);
                } else {
                    rc.used = true;
                    // Update recovery_codes to reflect new used code
                    sqlx::query!(
                        r#"
                            UPDATE users
                            SET two_factor_recovery_codes = $1
                            WHERE id = $2
                        "#,
                        SqlxJson(&*user.two_factor_recovery_codes.clone().unwrap()) as _,
                        user.id,
                    )
                    .execute(&pool)
                    .await?;
                }
            } else {
                return Err(AppError::InvalidOrExpiredCode);
            }
        }
    }

    let (access_token_jwt, refresh_token_db_string, expires_in) =
        create_tokens(&pool, user.id, &headers, &original_uri).await?;

    // Delete challenge (and expired ones)
    sqlx::query!(
        r#"
            DELETE FROM login_challenges
            WHERE id = $1 OR expires_at <= now()
        "#,
        &payload.challenge_id,
    )
    .execute(&pool)
    .await?;

    Ok(Json(AuthResponse {
        access_token: access_token_jwt,
        refresh_token: refresh_token_db_string,
        token_type: "Bearer".to_string(),
        expires_in,
        user: PublicUser::from(user),
    }))
}

pub async fn setup_two_factor(
    State(pool): State<PgPool>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<SetupTwoFactorPayload>,
) -> Result<Json<SetupTwoFactorResponse>, AppError> {
    let user_auth = sqlx::query_as!(
        SetupTwoFactorUser,
        r#"
            SELECT two_factor_secret, password_hash
            FROM users
            WHERE id = $1
        "#,
        user.id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::WrongCredentials)?;

    let parsed_hash = PasswordHash::new(&user_auth.password_hash)?;
    let passwords_match =
        Argon2::default().verify_password(&payload.password.as_bytes(), &parsed_hash);

    if !passwords_match.is_ok() {
        return Err(AppError::WrongCredentials);
    }

    if user_auth.two_factor_secret.is_some() {
        return Err(AppError::TwoFactorEnabledAlready);
    }

    let new_secret = Secret::default();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        new_secret.to_bytes().unwrap(),
        Some("Turbo Pancake".to_string()),
        user.username,
    )?;

    sqlx::query!(
        r#"
            UPDATE users
            SET two_factor_temp_secret = $1, two_factor_temp_expires = $2
            WHERE id = $3
        "#,
        new_secret.to_encoded().to_string(),
        Utc::now() + Duration::minutes(15),
        user.id,
    )
    .execute(&pool)
    .await?;

    Ok(Json(SetupTwoFactorResponse {
        otpauth_url: totp.get_url(),
        secret: new_secret.to_encoded().to_string(),
    }))
}

pub async fn confirm_two_factor(
    State(pool): State<PgPool>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<ConfirmTwoFactorPayload>,
) -> Result<Json<ConfirmTwoFactorResponse>, AppError> {
    let user_auth = sqlx::query_as!(
        ConfirmTwoFactorUser,
        r#"
            SELECT two_factor_secret, two_factor_temp_secret
            FROM users
            WHERE id = $1 AND two_factor_temp_expires > now()
        "#,
        user.id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::TwoFactorSecretNotFound)?;

    if user_auth.two_factor_secret.is_some() {
        sqlx::query!(
            r#"
                UPDATE users
                SET two_factor_temp_secret = NULL, two_factor_temp_expires = NULL
                WHERE id = $1
            "#,
            user.id,
        )
        .execute(&pool)
        .await?;

        return Err(AppError::TwoFactorEnabledAlready);
    }

    let secret = Secret::Encoded(user_auth.two_factor_temp_secret.clone().unwrap());

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_bytes().unwrap(),
        Some("Turbo Pancake".to_string()),
        user.username,
    )?;

    let matches = totp.check_current(&payload.code)?;

    if !matches {
        return Err(AppError::InvalidOrExpiredCode);
    }

    let codes = generate_recovery_code_structs(10);

    sqlx::query!(
        r#"
            UPDATE users
            SET two_factor_secret = $1, two_factor_temp_secret = NULL,
                two_factor_temp_expires = NULL, two_factor_recovery_codes = $2
            WHERE id = $3
        "#,
        user_auth.two_factor_temp_secret,
        SqlxJson(codes.clone()) as _,
        user.id,
    )
    .execute(&pool)
    .await?;

    Ok(Json(ConfirmTwoFactorResponse {
        codes: codes.into_iter().map(|rc| rc.code).collect(),
    }))
}

pub async fn verify_password(
    State(pool): State<PgPool>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<VerifyPasswordPayload>,
) -> Result<(), AppError> {
    let user_auth = sqlx::query_as!(
        VerifyPasswordUser,
        r#"SELECT password_hash FROM users WHERE id = $1"#,
        user.id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::InvalidToken)?;

    let parsed_hash = PasswordHash::new(&user_auth.password_hash)?;
    let passwords_match =
        Argon2::default().verify_password(&payload.password.as_bytes(), &parsed_hash);

    if !passwords_match.is_ok() {
        return Err(AppError::WrongCredentials);
    }

    Ok(())
}

pub async fn disable_2fa(
    State(pool): State<PgPool>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<Disable2FAPayload>,
) -> Result<(), AppError> {
    let user_auth = sqlx::query_as!(
        Disable2FAUser,
        r#"
            SELECT password_hash, two_factor_secret
            FROM users
            WHERE id = $1
        "#,
        user.id
    )
    .fetch_optional(&pool)
    .await?
    .ok_or(AppError::InvalidToken)?;

    let parsed_hash = PasswordHash::new(&user_auth.password_hash)?;
    let passwords_match =
        Argon2::default().verify_password(&payload.password.as_bytes(), &parsed_hash);

    if !passwords_match.is_ok() {
        return Err(AppError::WrongCredentials);
    }

    if let Some(secret) = user_auth.two_factor_secret {
        let secret = Secret::Encoded(secret);

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            Some("Turbo Pancake".to_string()),
            user.username,
        )?;

        let matches = totp.check_current(&payload.code)?;

        if !matches {
            return Err(AppError::InvalidOrExpiredCode);
        }

        sqlx::query!(
            r#"
                UPDATE users
                SET two_factor_secret = NULL, two_factor_temp_secret = NULL,
                    two_factor_temp_expires = NULL, two_factor_recovery_codes = NULL
                WHERE id = $1
            "#,
            user.id,
        )
        .execute(&pool)
        .await?;
    } else {
        return Err(AppError::TwoFactorSecretNotFound);
    }

    Ok(())
}

pub fn generate_email_code() -> String {
    let code: String = rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .map(|c| c.to_ascii_uppercase())
        .collect();

    code
}

async fn send_email(
    resend: &Resend,
    to: Vec<&str>,
    subject: &str,
    html: &str,
) -> Result<(), AppError> {
    let from = "Turbo Pancake <noreply@updates.mart1d4.dev>";
    let email = CreateEmailBaseOptions::new(from, to, subject).with_html(html);
    resend.emails.send(email).await.map_err(|e| {
        tracing::error!("Email send error: {:?}", e);
        AppError::EmailSendingFailed
    })?;
    Ok(())
}

pub async fn modify_email(
    State(state): State<AppState>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<ModifyEmailPayload>,
) -> Result<(), AppError> {
    let db_user = sqlx::query_as!(
        ModifyEmailUser,
        r#"
            SELECT email, email_verification_code
            FROM users
            WHERE id = $1
        "#,
        user.id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::InvalidToken)?;

    match (
        &db_user.email,
        &db_user.email_verification_code,
        &payload.code,
    ) {
        // Verify existing code
        (Some(_), Some(code), Some(provided)) if provided == code => {
            sqlx::query!(
                r#"UPDATE users SET email_verification_code = $1 WHERE id = $2"#,
                None as Option<String>,
                user.id,
            )
            .execute(&state.db)
            .await?;

            let token = issue_email_verification_token(user.id, payload.new_email.clone())
                .map_err(|_| AppError::TokenCreation)?;

            let content = format!(
                "<strong>Hey {}, you need to verify this email in order to add it to your account!</strong><br/><a href=\"https://turbo.pancake.dev/email/verify?token={}\">Click this link!<a/>",
                &user.username, token
            );

            send_email(
                &state.resend,
                vec![&payload.new_email],
                "Confirm your new email",
                &content,
            )
            .await?;
        }

        // Wrong or missing code
        (Some(_), Some(_), _) => return Err(AppError::WrongEmailCode),

        // Send new code for existing email
        (Some(email), None, _) => {
            let code = generate_email_code();

            sqlx::query!(
                r#"UPDATE users SET email_verification_code = $1 WHERE id = $2"#,
                code,
                user.id,
            )
            .execute(&state.db)
            .await?;

            let content = format!(
                "<strong>Hey {}, you need to verify this email in order to change it!</strong><br/><strong>{}<strong/>",
                &user.username, code
            );

            send_email(&state.resend, vec![email], "Verify your email", &content).await?;
        }

        // No email set yet
        (None, _, _) => {
            let token = issue_email_verification_token(user.id, payload.new_email.clone())
                .map_err(|_| AppError::TokenCreation)?;

            let content = format!(
                "<strong>Hey {}, you need to verify this email in order to add it to your account!</strong><br/><a href=\"https://turbo.pancake.dev/email/verify?token={}\">Click this link!<a/>",
                &user.username, token
            );

            send_email(
                &state.resend,
                vec![&payload.new_email],
                "Confirm your new email",
                &content,
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn confirm_email(
    State(pool): State<PgPool>,
    user: AuthorizedUser,
    ValidatedJson(payload): ValidatedJson<ConfirmEmailPayload>,
) -> Result<(), AppError> {
    let claims = decode_email_verification_token(payload.token)?;

    if claims.sub != user.id || claims.exp <= Utc::now().timestamp() as usize {
        return Err(AppError::InvalidToken);
    }

    sqlx::query!(
        r#"
            UPDATE users
            SET email = $1, email_verification_expires = NULL, email_verification_code = NULL
            WHERE id = $2
        "#,
        claims.new_email,
        user.id,
    )
    .execute(&pool)
    .await?;

    Ok(())
}
