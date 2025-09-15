use axum::Json;

use crate::{auth::jwt::AuthorizedUser, errors::AppError};

pub async fn protected_route(user: AuthorizedUser) -> Result<Json<String>, AppError> {
    Ok(Json(format!(
        "Welcome to the protected area, user ID: {}, username: {}",
        user.id, user.username
    )))
}
