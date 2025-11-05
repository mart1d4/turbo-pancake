use crate::types::PublicUser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError, ValidationErrors};

// --- Request Payloads ---
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterPayload {
    #[validate(
        length(min = 2, max = 32, message = "Must be between 2 to 32 characters.",),
        custom(function = "validate_username")
    )]
    pub username: String,
    #[validate(length(min = 4, max = 256, message = "Must be between 4 to 256 characters."))]
    pub password: String,
}

fn validate_username(username: &str) -> Result<(), ValidationError> {
    let forbidden_usernames: Vec<&str> = vec![
        "spark",
        "everyone",
        "here",
        "turbo",
        "pancake",
        "fictional",
        "potato",
    ];

    if forbidden_usernames.contains(&username) {
        return Err(ValidationError::new("Forbidden username"));
    }

    let regex = Regex::new(r"^[A-Za-z0-9._]+$").unwrap();
    if !regex.is_match(&username) {
        return Err(ValidationError::new(
            "Username can only contain letters, numbers, underscores and periods.",
        ));
    }

    Ok(())
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

#[derive(Debug, Deserialize, Validate)]
pub struct VerifyPasswordPayload {
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct Disable2FAPayload {
    pub password: String,
    #[validate(length(equal = 6))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ModifyEmailPayload {
    #[validate(email)]
    pub new_email: String,
    #[validate(length(equal = 6))]
    pub code: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ConfirmEmailPayload {
    pub token: String,
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
