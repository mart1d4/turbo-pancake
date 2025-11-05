use std::{fmt::Formatter, time::SystemTimeError};

use axum::{
    Json,
    extract::rejection::{BytesRejection, JsonRejection, PathRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use resend_rs::{Resend, types::ErrorKind};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use totp_rs::TotpUrlError;
use tower::timeout::error;
use validator::ValidationErrors;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorDetails {
    pub code: i64,
    pub message: String,
    pub details: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResponseError {
    pub error: ErrorDetails,
}

#[derive(Debug, Error)]
pub enum Resource {
    User,
    Channel,
    Guild,
    Role,
    Message,
    Emoji,
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Wrong credentials were provided.")]
    WrongCredentials,
    #[error("Wrong email code provided.")]
    WrongEmailCode,
    #[error("User doesn't have any email set.")]
    EmailNotSet,
    #[error("User has an email set already.")]
    EmailAlreadySet,
    #[error("Token creation failed.")]
    TokenCreation,
    #[error("Invalid access token provided.")]
    InvalidToken,
    #[error("Couldn't find resource: {0}.")]
    ResourceNotFound(Resource),
    #[error("User with this username already exists.")]
    UserAlreadyExists,
    #[error("The provided password is too weak.")]
    PasswordTooWeak,
    #[error("Failed to fetch URL: {0}.")]
    FetchingError(#[from] reqwest::Error),
    #[error("Database error: {0}.")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Expired token provided.")]
    ExpiredToken,
    #[error("Password hashing failed.")]
    PasswordHashingFailed(#[from] argon2::password_hash::Error),
    #[error("Invalid JSON body: {0}.")]
    JsonRejection(#[from] JsonRejection),
    #[error("Invalid query parameters: {0}.")]
    QueryRejection(#[from] QueryRejection),
    #[error("Invalid path parameters: {0}.")]
    PathRejection(#[from] PathRejection),
    #[error("Body bytes extraction error: {0}.")]
    BytesRejection(#[from] BytesRejection),
    #[error("Invalid JSON body: {0}.")]
    InvalidJson(#[from] ValidationErrors),
    #[error("Invalid or expired challenge ID provided.")]
    InvalidOrExpiredChallenge,
    #[error("Invalid or expired 2FA code provided.")]
    InvalidOrExpiredCode,
    #[error("Invalid 2FA token provided.")]
    InvalidTwoFactorToken(#[from] SystemTimeError),
    #[error("TOTP URL creation failed: {0}.")]
    TotpUrlError(#[from] TotpUrlError),
    #[error("2FA already activated on this account.")]
    TwoFactorEnabledAlready,
    #[error("User doesn't have a two factor secret set.")]
    TwoFactorSecretNotFound,
    #[error("Email sending failed.")]
    EmailSendingFailed,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, client_message, internal_details) = match &self {
            AppError::WrongCredentials => (
                StatusCode::UNAUTHORIZED,
                "Identifier or password is incorrect.",
                self.to_string(),
            ),
            AppError::WrongEmailCode => (
                StatusCode::UNAUTHORIZED,
                "The code you provided is incorrect.",
                self.to_string(),
            ),
            AppError::EmailNotSet => (
                StatusCode::BAD_REQUEST,
                "This user does not have an email.",
                self.to_string(),
            ),
            AppError::EmailAlreadySet => (
                StatusCode::BAD_REQUEST,
                "This user has an email already.",
                self.to_string(),
            ),
            AppError::EmailSendingFailed => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Please try again later.",
                self.to_string(),
            ),
            AppError::TokenCreation => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create authentication token.",
                self.to_string(),
            ),
            AppError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication token is invalid.",
                self.to_string(),
            ),
            AppError::UserAlreadyExists => (
                StatusCode::CONFLICT,
                "User with this username already exists.",
                self.to_string(),
            ),
            AppError::DatabaseError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Please try again later.",
                format!("Database error: {}", e),
            ),
            AppError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication token has expired.",
                self.to_string(),
            ),
            AppError::FetchingError(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Please try again later.",
                format!("Reqwest error: {}", e),
            ),
            AppError::PasswordTooWeak => (
                StatusCode::BAD_REQUEST,
                "The password you provided is too weak.",
                self.to_string(),
            ),
            AppError::PasswordHashingFailed(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Please try again later.",
                format!("Password hashing error: {}", e),
            ),
            AppError::ResourceNotFound(res) => (
                StatusCode::NOT_FOUND,
                "Resource not found.",
                format!("Resource {} wasn't found.", res),
            ),
            AppError::InvalidJson(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid form body.",
                format!("Invalid body provided (validation): {}.", e),
            ),
            AppError::InvalidOrExpiredChallenge => (
                StatusCode::BAD_REQUEST,
                "Invalid or expired challenge ID provided.",
                self.to_string(),
            ),
            AppError::InvalidOrExpiredCode => (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired code provided.",
                self.to_string(),
            ),
            AppError::InvalidTwoFactorToken(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong. Please try again later.",
                format!("Invalid two factor code provided: {}", e),
            ),
            AppError::TotpUrlError(e) => (
                StatusCode::UNAUTHORIZED,
                "Something went wrong. Please try again later.",
                format!("TOTP URL error: {}", e),
            ),
            AppError::TwoFactorEnabledAlready => (
                StatusCode::BAD_REQUEST,
                "You already have two factor authentication enabled.",
                self.to_string(),
            ),
            AppError::TwoFactorSecretNotFound => (
                StatusCode::NOT_FOUND,
                "Two factor secret not found for this account.",
                self.to_string(),
            ),

            // Extractor Rejection Mappings
            AppError::JsonRejection(e) => match e {
                JsonRejection::MissingJsonContentType(_) => (
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "Content-Type header must be application/json.",
                    e.to_string(),
                ),
                JsonRejection::JsonSyntaxError(_) => (
                    StatusCode::BAD_REQUEST,
                    "Malformed JSON in request body.",
                    e.to_string(),
                ),
                JsonRejection::JsonDataError(e) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Request body is valid JSON but has incorrect fields.",
                    format!("JSON deserialization error: {}", e),
                ),
                _ => (
                    StatusCode::BAD_REQUEST,
                    "Invalid JSON request.",
                    e.to_string(),
                ),
            },
            AppError::QueryRejection(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid query parameters.",
                e.to_string(),
            ),
            AppError::PathRejection(e) => (
                StatusCode::BAD_REQUEST,
                "Invalid path parameters.",
                e.to_string(),
            ),
            AppError::BytesRejection(e) => (
                StatusCode::BAD_REQUEST,
                "Failed to read request body.",
                e.to_string(),
            ),
        };

        let error_body = Json(json!({
            "error": {
                "code": status.as_u16(),
                "message": client_message,
                // Only include internal_details in development/debug mode
                // In production, log internal_details but don't expose to client
                "details": internal_details,
            }
        }));

        (status, error_body).into_response()
    }
}
