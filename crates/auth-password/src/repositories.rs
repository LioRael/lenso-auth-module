use crate::config::{AuthPasswordConfig, TokenStrategy};
use crate::jwt;
use crate::password::{
    hash_password, new_session_token, normalize_identifier, validate_password, verify_password,
};
use auth::public::{self, AuthSession, AuthUserId, SessionCreateOptions};
use auth::session_policy::{AllowSessionPolicy, AuthSessionPolicy};
use chrono::{DateTime, Duration, Utc};
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};

const PASSWORD_PROVIDER: &str = "password";
const MAX_FAILED_LOGINS: i32 = 5;
const LOGIN_FAILURE_WINDOW: Duration = Duration::minutes(15);
const LOGIN_LOCKOUT_DURATION: Duration = Duration::minutes(15);

#[derive(Debug, Clone)]
pub struct PasswordAuthRepository {
    pool: DbPool,
    session_policy: std::sync::Arc<dyn AuthSessionPolicy>,
}

/// Token returned by register/login, varying by strategy.
#[derive(Debug)]
pub enum AuthToken {
    Session(AuthSession),
    Jwt {
        user_id: String,
        token: String,
        expires_at: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordSessionOptions {
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
}

impl PasswordAuthRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self::new_with_session_policy(pool, std::sync::Arc::new(AllowSessionPolicy))
    }

    #[must_use]
    pub fn new_with_session_policy(
        pool: DbPool,
        session_policy: std::sync::Arc<dyn AuthSessionPolicy>,
    ) -> Self {
        Self {
            pool,
            session_policy,
        }
    }

    pub async fn register(
        &self,
        identifier: &str,
        password: &str,
        user_id: String,
        identity_id: String,
        session_id: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        config: &AuthPasswordConfig,
    ) -> AppResult<AuthToken> {
        self.register_with_options(
            identifier,
            password,
            user_id,
            identity_id,
            session_id,
            now,
            expires_at,
            config,
            PasswordSessionOptions::default(),
        )
        .await
    }

    pub async fn register_with_options(
        &self,
        identifier: &str,
        password: &str,
        user_id: String,
        identity_id: String,
        session_id: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        config: &AuthPasswordConfig,
        options: PasswordSessionOptions,
    ) -> AppResult<AuthToken> {
        let normalized_identifier = normalize_identifier(identifier)?;
        validate_password(password)?;
        let password_hash = hash_password(password, config)?;

        match config.token_strategy {
            TokenStrategy::Session => {
                let token = new_session_token();
                let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
                let identity = public::create_user_identity_in_tx(
                    &mut tx,
                    AuthUserId(user_id),
                    identity_id,
                    PASSWORD_PROVIDER,
                    &normalized_identifier,
                    now,
                )
                .await?;

                sqlx::query(
                    r#"
                    insert into auth_password.credentials (identity_id, password_hash, created_at, updated_at)
                    values ($1, $2, $3, $3)
                    "#,
                )
                .bind(&identity.id)
                .bind(password_hash)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(map_sql_error)?;

                let session = public::create_session_in_tx_with_policy(
                    &mut tx,
                    &identity.user_id,
                    session_id,
                    token,
                    now,
                    expires_at,
                    SessionCreateOptions {
                        device_id: options.device_id,
                        client: options.client,
                    },
                    self.session_policy.as_ref(),
                )
                .await?;

                tx.commit().await.map_err(map_sql_error)?;
                Ok(AuthToken::Session(session))
            }
            TokenStrategy::Jwt => {
                let jwt_config = config.jwt_config()?.ok_or_else(|| {
                    AppError::new(ErrorCode::Internal, "JWT configuration is required")
                })?;
                let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
                let identity = public::create_user_identity_in_tx(
                    &mut tx,
                    AuthUserId(user_id),
                    identity_id,
                    PASSWORD_PROVIDER,
                    &normalized_identifier,
                    now,
                )
                .await?;

                sqlx::query(
                    r#"
                    insert into auth_password.credentials (identity_id, password_hash, created_at, updated_at)
                    values ($1, $2, $3, $3)
                    "#,
                )
                .bind(&identity.id)
                .bind(password_hash)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(map_sql_error)?;

                tx.commit().await.map_err(map_sql_error)?;

                let user_id_str = identity.user_id.0.clone();
                let token = jwt::create_token(&user_id_str, &jwt_config, now);

                Ok(AuthToken::Jwt {
                    user_id: user_id_str,
                    token,
                    expires_at,
                })
            }
        }
    }

    pub async fn login(
        &self,
        identifier: &str,
        password: &str,
        session_id: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        config: &AuthPasswordConfig,
    ) -> AppResult<AuthToken> {
        self.login_with_options(
            identifier,
            password,
            session_id,
            now,
            expires_at,
            config,
            PasswordSessionOptions::default(),
        )
        .await
    }

    pub async fn login_with_options(
        &self,
        identifier: &str,
        password: &str,
        session_id: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        config: &AuthPasswordConfig,
        options: PasswordSessionOptions,
    ) -> AppResult<AuthToken> {
        let normalized_identifier = normalize_identifier(identifier)?;
        validate_password(password)?;
        self.ensure_login_not_locked(&normalized_identifier, now)
            .await?;

        let Some(identity) =
            public::find_active_identity(&self.pool, PASSWORD_PROVIDER, &normalized_identifier)
                .await?
        else {
            self.record_failed_login(&normalized_identifier, now, &options.client)
                .await?;
            return Err(invalid_credentials());
        };

        let Some(password_hash) = sqlx::query_scalar::<_, String>(
            r#"
            select password_hash
            from auth_password.credentials
            where identity_id = $1
            "#,
        )
        .bind(&identity.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?
        else {
            self.record_failed_login(&normalized_identifier, now, &options.client)
                .await?;
            return Err(invalid_credentials());
        };

        if !verify_password(&password_hash, password)? {
            self.record_failed_login(&normalized_identifier, now, &options.client)
                .await?;
            return Err(invalid_credentials());
        }

        match config.token_strategy {
            TokenStrategy::Session => {
                let session = public::create_session_with_policy(
                    &self.pool,
                    &identity.user_id,
                    session_id,
                    new_session_token(),
                    now,
                    expires_at,
                    SessionCreateOptions {
                        device_id: options.device_id,
                        client: options.client,
                    },
                    self.session_policy.as_ref(),
                )
                .await?;
                self.clear_login_failures(&normalized_identifier).await?;
                Ok(AuthToken::Session(session))
            }
            TokenStrategy::Jwt => {
                let jwt_config = config.jwt_config()?.ok_or_else(|| {
                    AppError::new(ErrorCode::Internal, "JWT configuration is required")
                })?;
                let user_id_str = identity.user_id.0.clone();
                let token = jwt::create_token(&user_id_str, &jwt_config, now);
                self.clear_login_failures(&normalized_identifier).await?;
                Ok(AuthToken::Jwt {
                    user_id: user_id_str,
                    token,
                    expires_at,
                })
            }
        }
    }

    async fn ensure_login_not_locked(
        &self,
        normalized_identifier: &str,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        let locked_until = sqlx::query_scalar::<_, DateTime<Utc>>(
            r#"
            select locked_until
            from auth_password.login_failures
            where identifier = $1 and locked_until > $2
            "#,
        )
        .bind(normalized_identifier)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        match locked_until {
            Some(locked_until) => Err(rate_limited(locked_until)),
            None => Ok(()),
        }
    }

    async fn record_failed_login(
        &self,
        normalized_identifier: &str,
        now: DateTime<Utc>,
        client: &ClientRequestMetadata,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let row = sqlx::query_as::<_, (i32, DateTime<Utc>)>(
            r#"
            select failed_count, window_started_at
            from auth_password.login_failures
            where identifier = $1
            for update
            "#,
        )
        .bind(normalized_identifier)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        if let Some((failed_count, window_started_at)) = row {
            let update = failed_login_update(failed_count, window_started_at, now);
            sqlx::query(
                r#"
                update auth_password.login_failures
                set failed_count = $2,
                    window_started_at = $3,
                    last_failed_at = $4,
                    locked_until = $5,
                    last_failed_ip = $6,
                    last_failed_user_agent = $7
                where identifier = $1
                "#,
            )
            .bind(normalized_identifier)
            .bind(update.failed_count)
            .bind(update.window_started_at)
            .bind(now)
            .bind(update.locked_until)
            .bind(client.ip.as_deref())
            .bind(client.user_agent.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(map_sql_error)?;
        } else {
            sqlx::query(
                r#"
                insert into auth_password.login_failures
                    (
                        identifier,
                        failed_count,
                        window_started_at,
                        last_failed_at,
                        locked_until,
                        last_failed_ip,
                        last_failed_user_agent
                    )
                values ($1, 1, $2, $2, null, $3, $4)
                "#,
            )
            .bind(normalized_identifier)
            .bind(now)
            .bind(client.ip.as_deref())
            .bind(client.user_agent.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(map_sql_error)?;
        }

        tx.commit().await.map_err(map_sql_error)?;
        Ok(())
    }

    async fn clear_login_failures(&self, normalized_identifier: &str) -> AppResult<()> {
        sqlx::query(
            r#"
            delete from auth_password.login_failures
            where identifier = $1
            "#,
        )
        .bind(normalized_identifier)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;
        Ok(())
    }
}

fn invalid_credentials() -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Invalid identifier or password")
}

fn rate_limited(locked_until: DateTime<Utc>) -> AppError {
    AppError::new(
        ErrorCode::RateLimited,
        format!(
            "Too many password login attempts; try again after {}",
            locked_until.to_rfc3339()
        ),
    )
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FailedLoginUpdate {
    failed_count: i32,
    window_started_at: DateTime<Utc>,
    locked_until: Option<DateTime<Utc>>,
}

fn failed_login_update(
    failed_count: i32,
    window_started_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> FailedLoginUpdate {
    if now - window_started_at > LOGIN_FAILURE_WINDOW {
        return FailedLoginUpdate {
            failed_count: 1,
            window_started_at: now,
            locked_until: None,
        };
    }

    let failed_count = failed_count + 1;
    FailedLoginUpdate {
        failed_count,
        window_started_at,
        locked_until: (failed_count >= MAX_FAILED_LOGINS).then_some(now + LOGIN_LOCKOUT_DURATION),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn failed_login_update_locks_on_fifth_failure_in_window() {
        let now = Utc::now();
        let update = failed_login_update(4, now - Duration::minutes(1), now);

        assert_eq!(update.failed_count, 5);
        assert_eq!(update.window_started_at, now - Duration::minutes(1));
        assert_eq!(update.locked_until, Some(now + LOGIN_LOCKOUT_DURATION));
    }

    #[test]
    fn failed_login_update_resets_expired_window() {
        let now = Utc::now();
        let update = failed_login_update(4, now - LOGIN_FAILURE_WINDOW - Duration::seconds(1), now);

        assert_eq!(update.failed_count, 1);
        assert_eq!(update.window_started_at, now);
        assert_eq!(update.locked_until, None);
    }
}
