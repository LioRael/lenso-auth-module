use platform_core::error::ErrorDetail;
use platform_core::{AppError, AppResult};

const MIN_E164_DIGITS: usize = 8;
const MAX_E164_DIGITS: usize = 15;

pub fn normalize_phone_e164(phone: &str) -> AppResult<String> {
    let trimmed = phone.trim();
    let digits = trimmed
        .strip_prefix('+')
        .ok_or_else(|| validation_error("phone"))?;

    if digits.len() < MIN_E164_DIGITS
        || digits.len() > MAX_E164_DIGITS
        || !digits.chars().all(|char| char.is_ascii_digit())
        || digits.starts_with('0')
    {
        return Err(validation_error("phone"));
    }

    Ok(format!("+{digits}"))
}

fn validation_error(field: &str) -> AppError {
    AppError::validation(
        "Request validation failed",
        vec![ErrorDetail {
            field: Some(field.to_owned()),
            reason: "phone must be a canonical E.164 number".to_owned(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_trimmed_e164_phone_numbers() {
        assert_eq!(
            normalize_phone_e164("  +8613800000000  ").expect("phone should normalize"),
            "+8613800000000"
        );
    }

    #[test]
    fn rejects_non_e164_phone_numbers() {
        assert!(normalize_phone_e164("13800000000").is_err());
        assert!(normalize_phone_e164("+86 abc").is_err());
        assert!(normalize_phone_e164("+").is_err());
    }
}
