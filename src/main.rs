mod auth;
mod errors;
mod extractors;
mod handlers;
mod models;
mod state;
mod types;

use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde_json::json;
use sqlx::PgPool;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    handlers::{
        auth::{check_2fa, confirm_two_factor, login, refresh_token, register, setup_two_factor},
        protected::protected_route,
    },
    state::AppState,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("Failed to create Postgres pool");

    let app_state = AppState { db: pool };

    let app = Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/login/2fa", post(check_2fa))
        .route("/auth/2fa/setup", post(setup_two_factor))
        .route("/auth/2fa/confirm", post(confirm_two_factor))
        //.route("/auth/2fa", delete())
        .route("/auth/refresh", post(refresh_token))
        .route("/protected", get(protected_route))
        .with_state(app_state)
        .fallback(handler_404);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .expect("PORT must be a valid number");

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn handler_404() -> impl IntoResponse {
    let body = Json(json!({
        "error": {
            "code": 404,
            "message": "Nothing found",
            "details": "Nothing found",
        }
    }));

    (StatusCode::NOT_FOUND, body)
}
