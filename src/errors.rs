use axum::{
    Json,
    extract::rejection::{BytesRejection, JsonRejection, PathRejection, QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

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
pub enum AppError {
    #[error("Wrong credentials")]
    WrongCredentials,
    #[error("Token creation error")]
    TokenCreation,
    #[error("Invalid access token")]
    InvalidToken,
    #[error("User with this email or username already exists")]
    UserAlreadyExists,
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Expired token")]
    ExpiredToken,
    #[error("Password hashing failed")]
    PasswordHashingFailed(#[from] bcrypt::BcryptError),
    #[error("Invalid JSON body: {0}")]
    JsonRejection(#[from] JsonRejection),
    #[error("Invalid query parameters: {0}")]
    QueryRejection(#[from] QueryRejection),
    #[error("Invalid path parameters: {0}")]
    PathRejection(#[from] PathRejection),
    #[error("Body bytes extraction error: {0}")]
    BytesRejection(#[from] BytesRejection),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, client_message, internal_details) = match &self {
            // --- Application-specific Error Mappings ---
            AppError::WrongCredentials => (
                StatusCode::UNAUTHORIZED,
                "Username or password is incorrect.",
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
                "A database error occurred.",
                format!("Database error: {}", e),
            ),
            AppError::ExpiredToken => (
                StatusCode::UNAUTHORIZED,
                "Authentication token has expired.",
                self.to_string(),
            ),
            AppError::PasswordHashingFailed(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Password processing failed.",
                format!("Password hashing error: {}", e),
            ),

            // --- Extractor Rejection Mappings ---
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

        // Construct the consistent JSON error object
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
