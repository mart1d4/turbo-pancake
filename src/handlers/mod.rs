pub mod auth;
pub mod protected;

// Re-exports for convenience
pub use auth::{login, refresh_token, register};
pub use protected::protected_route;
