use crate::config::AuthPhoneConfig;
use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use platform_core::error::ErrorDetail;
use platform_core::{AppError, AppResult, ErrorCode};

const MAX_PASSWORD_BYTES: usize = 1024;

pub fn validate_password(password: &str, config: &AuthPhoneConfig) -> AppResult<()> {
    if password.len() < config.password_min_length || password.len() > MAX_PASSWORD_BYTES {
        return Err(validation_error("password", "password is invalid"));
    }

    Ok(())
}

pub fn hash_password(password: &str, config: &AuthPhoneConfig) -> AppResult<String> {
    validate_password(password, config)?;

    let mut salt_bytes = [0u8; 16];
    getrandom::fill(&mut salt_bytes).expect("OS randomness should be available");
    let salt = SaltString::encode_b64(&salt_bytes)
        .expect("16 random bytes should produce a valid Argon2 salt");

    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AppError::new(ErrorCode::Internal, "Password hashing failed"))
}

pub fn verify_password(password_hash: &str, password: &str) -> AppResult<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(|source| {
        AppError::new(
            ErrorCode::Internal,
            format!("Stored password hash is invalid: {source}"),
        )
    })?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn validation_error(field: &str, reason: &str) -> AppError {
    AppError::validation(
        "Request validation failed",
        vec![ErrorDetail {
            field: Some(field.to_owned()),
            reason: reason.to_owned(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies_original_password_only() {
        let config = AuthPhoneConfig::default();
        let hash = hash_password("correct horse", &config).expect("password should hash");

        assert!(verify_password(&hash, "correct horse").expect("hash should verify"));
        assert!(!verify_password(&hash, "wrong horse").expect("hash should verify"));
    }

    #[test]
    fn password_validation_uses_configured_min_length() {
        let config = AuthPhoneConfig {
            password_min_length: 10,
            ..AuthPhoneConfig::default()
        };

        assert!(validate_password("123456789", &config).is_err());
        assert!(validate_password("1234567890", &config).is_ok());
    }
}
