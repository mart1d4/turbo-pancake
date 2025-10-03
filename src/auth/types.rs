use crate::types::PublicUser;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationErrors};

// --- Request Payloads ---
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterPayload {
    #[validate(length(min = 2, max = 32, message = "Must be between 2 to 32 characters."))]
    pub username: String,
    #[validate(length(min = 4, max = 256, message = "Must be between 4 to 256 characters."))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginPayload {
    pub identifier: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct Totp {
    #[validate(length(equal = 6))]
    pub totp_code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct Recovery {
    #[validate(length(equal = 17))]
    pub recovery_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TwoFactorLoginMethod {
    Totp(Totp),
    Recovery(Recovery),
}

#[derive(Debug, Deserialize)]
pub struct TwoFactorLoginPayload {
    #[serde(with = "serde_str")]
    pub challenge_id: i64,
    #[serde(flatten)]
    pub login_method: TwoFactorLoginMethod,
}

impl Validate for TwoFactorLoginPayload {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match &self.login_method {
            TwoFactorLoginMethod::Totp(code) => code.validate(),
            TwoFactorLoginMethod::Recovery(code) => code.validate(),
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct SetupTwoFactorPayload {
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ConfirmTwoFactorPayload {
    #[validate(length(equal = 6))]
    pub code: String,
}

// --- Response Bodies ---
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: usize,
    pub user: PublicUser,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Success(AuthResponse),
    TwoFactorRequired { challenge_id: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetupTwoFactorResponse {
    pub otpauth_url: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmTwoFactorResponse {
    pub codes: Vec<String>,
}
