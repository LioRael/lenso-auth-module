#[allow(dead_code)]
mod contract;

include!("generated.rs");

#[cfg(test)]
mod tests {
    use super::decode_create_response;

    #[test]
    fn pre_nonce_create_response_remains_decodable() {
        let response = decode_create_response(
            r#"{"state":"state","code_verifier":"verifier","code_challenge":"challenge","expires_at":"2026-08-30T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!(response.nonce, None);
    }
}
