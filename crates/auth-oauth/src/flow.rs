use auth::resolver::session_token_hash;
use chrono::{DateTime, Utc};
use platform_core::error::ErrorDetail;
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct OAuthFlowRepository {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthFlowInput {
    pub provider: String,
    pub return_to: String,
    pub client: ClientRequestMetadata,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthCreatedFlow {
    pub state: String,
    pub code_verifier: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthConsumedFlow {
    pub provider: String,
    pub code_verifier: String,
    pub return_to: String,
    pub client: ClientRequestMetadata,
    pub expires_at: DateTime<Utc>,
}

impl OAuthFlowRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_flow(&self, input: OAuthFlowInput) -> AppResult<OAuthCreatedFlow> {
        let state = new_token("oauth_state_");
        let code_verifier = new_token("oauth_verifier_");

        sqlx::query(
            r"
            insert into auth_oauth.flows (
                state_hash,
                provider,
                code_verifier,
                return_to,
                client_ip,
                user_agent,
                created_at,
                expires_at,
                consumed_at
            )
            values ($1, $2, $3, $4, $5, $6, $7, $8, null)
            ",
        )
        .bind(session_token_hash(&state))
        .bind(&input.provider)
        .bind(&code_verifier)
        .bind(&input.return_to)
        .bind(input.client.ip.as_deref())
        .bind(input.client.user_agent.as_deref())
        .bind(input.created_at)
        .bind(input.expires_at)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(OAuthCreatedFlow {
            state,
            code_verifier,
            expires_at: input.expires_at,
        })
    }

    pub async fn consume_flow(
        &self,
        provider: &str,
        state: &str,
        now: DateTime<Utc>,
    ) -> AppResult<Option<OAuthConsumedFlow>> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                DateTime<Utc>,
            ),
        >(
            r"
            update auth_oauth.flows
            set consumed_at = $3
            where state_hash = $1
              and provider = $2
              and consumed_at is null
              and expires_at > $3
            returning provider, code_verifier, return_to, client_ip, user_agent, expires_at
            ",
        )
        .bind(session_token_hash(state))
        .bind(provider)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(row.map(
            |(provider, code_verifier, return_to, ip, user_agent, expires_at)| OAuthConsumedFlow {
                provider,
                code_verifier,
                return_to,
                client: ClientRequestMetadata { ip, user_agent },
                expires_at,
            },
        ))
    }
}

fn new_token(prefix: &str) -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness should be available");

    let mut token = String::with_capacity(prefix.len() + bytes.len() * 2);
    token.push_str(prefix);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

pub fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_no_pad(digest.as_ref())
}

pub fn normalize_return_to(value: Option<&str>) -> AppResult<String> {
    let return_to = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("/");
    let encoded = return_to.to_ascii_lowercase();
    let valid = return_to.starts_with('/')
        && !return_to.starts_with("//")
        && !return_to.contains('\\')
        && !encoded.contains("%5c")
        && !return_to.contains('#')
        && return_to
            .bytes()
            .all(|byte| !byte.is_ascii_control() && byte != 0x7f);
    if valid {
        return Ok(return_to.to_owned());
    }

    Err(validation(
        "return_to",
        "return_to must be a safe relative path without fragments or backslashes",
    ))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];
        encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
        encoded.push(char::from(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]));
        encoded.push(char::from(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]));
        encoded.push(char::from(TABLE[(b2 & 0x3f) as usize]));
    }

    match chunks.remainder() {
        [b0] => {
            encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
            encoded.push(char::from(TABLE[((b0 & 0x03) << 4) as usize]));
        }
        [b0, b1] => {
            encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
            encoded.push(char::from(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]));
            encoded.push(char::from(TABLE[((b1 & 0x0f) << 2) as usize]));
        }
        [] => {}
        _ => unreachable!("remainder length is at most two"),
    }

    encoded
}

fn validation(field: &str, reason: &str) -> AppError {
    AppError::validation(
        "Request validation failed",
        vec![ErrorDetail {
            field: Some(field.to_owned()),
            reason: reason.to_owned(),
        }],
    )
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc_example() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn return_to_accepts_only_safe_relative_targets() {
        assert_eq!(normalize_return_to(None).unwrap(), "/");
        assert_eq!(
            normalize_return_to(Some("/console?tab=modules")).unwrap(),
            "/console?tab=modules"
        );
        assert!(normalize_return_to(Some("https://evil.example")).is_err());
        assert!(normalize_return_to(Some("//evil.example/path")).is_err());
        assert!(normalize_return_to(Some("/\\evil.example/path")).is_err());
        assert!(normalize_return_to(Some("/\\\\evil.example/path")).is_err());
        assert!(normalize_return_to(Some("/%5cevil.example/path")).is_err());
        assert!(normalize_return_to(Some("/%5Cevil.example/path")).is_err());
        assert!(normalize_return_to(Some("/console#token")).is_err());
        assert!(normalize_return_to(Some("/console\nLocation: https://evil.example")).is_err());
    }
}
