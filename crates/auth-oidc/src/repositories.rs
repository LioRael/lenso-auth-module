use auth::models::AuthUserId;
use auth::resolver::session_token_hash;
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, DbPool, ErrorCode};
use std::fmt::Write as _;

#[derive(Debug, Clone)]
pub struct OidcRepository {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeInput {
    pub user_id: AuthUserId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub code: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRecord {
    pub user_id: AuthUserId,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
    pub expires_at: DateTime<Utc>,
}

impl OidcRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_authorization_code(
        &self,
        input: AuthorizationCodeInput,
    ) -> AppResult<AuthorizationCode> {
        let code = new_authorization_code();
        let result = sqlx::query(
            r"
            insert into auth_oidc.authorization_codes (
                code_hash,
                user_id,
                client_id,
                redirect_uri,
                scope,
                code_challenge,
                code_challenge_method,
                nonce,
                created_at,
                expires_at,
                consumed_at
            )
            select $1, users.id, $3, $4, $5, $6, $7, $8, $9, $10, null
            from auth.users users
            where users.id = $2
              and (users.disabled_at is null or users.disabled_until <= now())
            ",
        )
        .bind(session_token_hash(&code))
        .bind(&input.user_id.0)
        .bind(&input.client_id)
        .bind(&input.redirect_uri)
        .bind(&input.scope)
        .bind(&input.code_challenge)
        .bind(&input.code_challenge_method)
        .bind(input.nonce.as_deref())
        .bind(input.created_at)
        .bind(input.expires_at)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        if result.rows_affected() == 0 {
            return Err(AppError::new(ErrorCode::Forbidden, "Auth user is disabled"));
        }

        Ok(AuthorizationCode {
            code,
            expires_at: input.expires_at,
        })
    }

    pub async fn find_authorization_code(
        &self,
        code: &str,
        now: DateTime<Utc>,
    ) -> AppResult<Option<AuthorizationCodeRecord>> {
        let row = sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                String,
                String,
                Option<String>,
                DateTime<Utc>,
            ),
        >(
            r"
            select
                user_id,
                client_id,
                redirect_uri,
                scope,
                code_challenge,
                code_challenge_method,
                nonce,
                expires_at
            from auth_oidc.authorization_codes
            where code_hash = $1
              and consumed_at is null
              and expires_at > $2
            ",
        )
        .bind(session_token_hash(code))
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(row.map(
            |(
                user_id,
                client_id,
                redirect_uri,
                scope,
                code_challenge,
                code_challenge_method,
                nonce,
                expires_at,
            )| AuthorizationCodeRecord {
                user_id: AuthUserId(user_id),
                client_id,
                redirect_uri,
                scope,
                code_challenge,
                code_challenge_method,
                nonce,
                expires_at,
            },
        ))
    }

    pub async fn consume_authorization_code(
        &self,
        code: &str,
        now: DateTime<Utc>,
    ) -> AppResult<bool> {
        let result = sqlx::query(
            r"
            update auth_oidc.authorization_codes
            set consumed_at = $2
            where code_hash = $1
              and consumed_at is null
              and expires_at > $2
            ",
        )
        .bind(session_token_hash(code))
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(result.rows_affected() == 1)
    }
}

fn new_authorization_code() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness should be available");

    let mut token = String::with_capacity("oidc_code_".len() + bytes.len() * 2);
    token.push_str("oidc_code_");
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_codes_use_oidc_prefix() {
        assert!(new_authorization_code().starts_with("oidc_code_"));
    }
}
