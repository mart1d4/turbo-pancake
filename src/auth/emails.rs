use std::env;

use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::errors::AppError;

#[derive(Serialize, Deserialize)]
pub struct EmailChangeToken {
    pub sub: i64,
    pub new_email: String,
    pub exp: usize,
}

pub fn issue_email_verification_token(user_id: i64, new_email: String) -> Result<String, AppError> {
    let token = encode(
        &Header::default(),
        &EmailChangeToken {
            sub: user_id,
            new_email: new_email,
            exp: (Utc::now() + Duration::minutes(60)).timestamp() as usize,
        },
        &EncodingKey::from_secret(
            env::var("EMAIL_TOKEN_SECRET")
                .expect("EMAIL_TOKEN_SECRET must be set")
                .as_bytes(),
        ),
    )
    .map_err(|_| AppError::TokenCreation)?;

    Ok(token)
}

pub fn decode_email_verification_token(token: String) -> Result<EmailChangeToken, AppError> {
    let data = decode::<EmailChangeToken>(
        &token,
        &DecodingKey::from_secret(
            env::var("EMAIL_TOKEN_SECRET")
                .expect("EMAIL_TOKEN_SECRET must be set")
                .as_bytes(),
        ),
        &Validation::default(),
    )
    .map_err(|_| AppError::InvalidToken)?;

    Ok(data.claims)
}
