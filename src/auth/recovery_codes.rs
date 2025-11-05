use rand::{Rng, distr::Alphanumeric, rng};

use crate::types::TwoFactorRecoveryCode;

pub fn generate_recovery_code() -> String {
    let code: String = rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .map(|c| c.to_ascii_uppercase())
        .collect();

    format!("{}-{}", &code[0..4], &code[4..8])
}

pub fn generate_recovery_codes(n: usize) -> Vec<String> {
    (0..n).map(|_| generate_recovery_code()).collect()
}

pub fn generate_recovery_code_structs(n: usize) -> Vec<TwoFactorRecoveryCode> {
    generate_recovery_codes(n)
        .into_iter()
        .map(|code| TwoFactorRecoveryCode { code, used: false })
        .collect()
}
