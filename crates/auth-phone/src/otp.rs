use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub fn new_otp_code(length: usize) -> String {
    let mut output = String::with_capacity(length);
    while output.len() < length {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).expect("OS randomness should be available");
        let digit = byte[0] % 10;
        output.push(char::from(b'0' + digit));
    }
    output
}

pub fn hash_otp_code(code: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":");
    hasher.update(code.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_otp_code_is_numeric_with_requested_length() {
        let code = new_otp_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|char| char.is_ascii_digit()));
    }

    #[test]
    fn otp_hash_changes_with_secret() {
        let first = hash_otp_code("123456", "secret-one");
        let second = hash_otp_code("123456", "secret-two");

        assert_ne!(first, "123456");
        assert_ne!(first, second);
        assert_eq!(first, hash_otp_code("123456", "secret-one"));
    }
}
