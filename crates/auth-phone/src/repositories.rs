use crate::config::AuthPhoneConfig;
use crate::otp::{hash_otp_code, new_otp_code};
use crate::password::{hash_password, validate_password, verify_password};
use crate::phone::normalize_phone_e164;
use auth::public::{self, AuthSession, AuthUserId, SessionCreateOptions};
use auth::session_policy::{AllowSessionPolicy, AuthSessionPolicy};
use chrono::{DateTime, Duration, Utc};
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;

const PHONE_PROVIDER: &str = "phone";
const MAX_FAILED_PASSWORD_LOGINS: i32 = 5;
const PASSWORD_LOGIN_FAILURE_WINDOW: Duration = Duration::minutes(15);
const PASSWORD_LOGIN_LOCKOUT_DURATION: Duration = Duration::minutes(15);

#[derive(Debug, Clone)]
pub struct PhoneAuthRepository {
    pool: DbPool,
    session_policy: Arc<dyn AuthSessionPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneOtpPurpose {
    SignIn,
    PasswordSetup,
    PasswordReset,
}

#[derive(Debug)]
pub struct StartOtpInput<'a> {
    pub phone: &'a str,
    pub purpose: PhoneOtpPurpose,
    pub challenge_id: String,
    pub now: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
    pub client: ClientRequestMetadata,
}

#[derive(Debug, Clone)]
pub struct PhoneOtpChallenge {
    pub id: String,
    pub phone_e164: String,
    pub purpose: PhoneOtpPurpose,
    pub expires_at: DateTime<Utc>,
    pub resend_after: DateTime<Utc>,
    pub debug_code: Option<String>,
}

#[derive(Debug)]
pub struct VerifyOtpOptions<'a> {
    pub challenge_id: &'a str,
    pub code: &'a str,
    pub session_id: String,
    pub user_id: String,
    pub identity_id: String,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
    pub link_anonymous_user_id: Option<AuthUserId>,
}

#[derive(Debug)]
pub struct SetPhonePasswordOptions<'a> {
    pub user_id: &'a AuthUserId,
    pub password: &'a str,
    pub now: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
}

#[derive(Debug)]
pub struct LoginPhonePasswordOptions<'a> {
    pub phone: &'a str,
    pub password: &'a str,
    pub session_id: String,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
}

impl PhoneAuthRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self::new_with_session_policy(pool, Arc::new(AllowSessionPolicy))
    }

    #[must_use]
    pub fn new_with_session_policy(
        pool: DbPool,
        session_policy: Arc<dyn AuthSessionPolicy>,
    ) -> Self {
        Self {
            pool,
            session_policy,
        }
    }

    pub async fn start_otp(&self, input: StartOtpInput<'_>) -> AppResult<PhoneOtpChallenge> {
        let StartOtpInput {
            phone,
            purpose,
            challenge_id,
            now,
            config,
            client,
        } = input;

        let _ = &self.session_policy;

        let phone_e164 = normalize_phone_e164(phone)?;
        let code = new_otp_code(config.otp_code_length);
        let code_hash = hash_otp_code(&code, &config.otp_secret);
        let expires_at = now + Duration::seconds(config.otp_ttl_seconds);
        let resend_after = now + Duration::seconds(config.otp_resend_cooldown_seconds);

        sqlx::query(
            r#"
            insert into auth_phone.otp_challenges (
                id,
                phone_e164,
                purpose,
                code_hash,
                attempts,
                max_attempts,
                created_at,
                expires_at,
                resend_after,
                consumed_at,
                client_ip,
                user_agent
            )
            values ($1, $2, $3, $4, 0, $5, $6, $7, $8, null, $9, $10)
            "#,
        )
        .bind(&challenge_id)
        .bind(&phone_e164)
        .bind(purpose.as_str())
        .bind(code_hash)
        .bind(config.otp_max_attempts)
        .bind(now)
        .bind(expires_at)
        .bind(resend_after)
        .bind(client.ip.as_deref())
        .bind(client.user_agent.as_deref())
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(PhoneOtpChallenge {
            id: challenge_id,
            phone_e164,
            purpose,
            expires_at,
            resend_after,
            debug_code: config.return_debug_otp_code.then_some(code),
        })
    }

    pub async fn consume_otp(
        &self,
        challenge_id: &str,
        code: &str,
        now: DateTime<Utc>,
        config: &AuthPhoneConfig,
    ) -> AppResult<Option<PhoneOtpChallenge>> {
        let _ = &self.session_policy;

        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let Some(row) = sqlx::query_as::<_, OtpChallengeRow>(
            r#"
            select id, phone_e164, purpose, code_hash, attempts, max_attempts, expires_at, resend_after, consumed_at
            from auth_phone.otp_challenges
            where id = $1
            for update
            "#,
        )
        .bind(challenge_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sql_error)?
        else {
            tx.commit().await.map_err(map_sql_error)?;
            return Ok(None);
        };

        let (
            id,
            phone_e164,
            purpose,
            code_hash,
            attempts,
            max_attempts,
            expires_at,
            resend_after,
            consumed_at,
        ) = row;

        if consumed_at.is_some() || expires_at <= now || attempts >= max_attempts {
            tx.commit().await.map_err(map_sql_error)?;
            return Ok(None);
        }

        if code_hash != hash_otp_code(code, &config.otp_secret) {
            increment_otp_attempts(&mut tx, challenge_id).await?;
            tx.commit().await.map_err(map_sql_error)?;
            return Ok(None);
        }

        sqlx::query(
            r#"
            update auth_phone.otp_challenges
            set consumed_at = $2
            where id = $1
            "#,
        )
        .bind(challenge_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        tx.commit().await.map_err(map_sql_error)?;

        Ok(Some(PhoneOtpChallenge {
            id,
            phone_e164,
            purpose: PhoneOtpPurpose::from_db(&purpose)?,
            expires_at,
            resend_after,
            debug_code: None,
        }))
    }

    pub async fn verify_otp_with_options(
        &self,
        input: VerifyOtpOptions<'_>,
    ) -> AppResult<Option<AuthSession>> {
        let VerifyOtpOptions {
            challenge_id,
            code,
            session_id,
            user_id,
            identity_id,
            now,
            expires_at,
            config,
            device_id,
            client,
            link_anonymous_user_id,
        } = input;

        let Some(challenge) = self.consume_otp(challenge_id, code, now, config).await? else {
            return Ok(None);
        };

        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let identity =
            match find_active_phone_identity_in_tx(&mut tx, &challenge.phone_e164).await? {
                Some(identity) => identity,
                None => match link_anonymous_user_id.as_ref() {
                    Some(link_user_id) => {
                        public::link_identity_to_anonymous_user_in_tx(
                            &mut tx,
                            link_user_id,
                            identity_id,
                            PHONE_PROVIDER,
                            &challenge.phone_e164,
                            now,
                        )
                        .await?
                    }
                    None => {
                        public::create_user_identity_in_tx(
                            &mut tx,
                            AuthUserId(user_id),
                            identity_id,
                            PHONE_PROVIDER,
                            &challenge.phone_e164,
                            now,
                        )
                        .await?
                    }
                },
            };

        upsert_phone_identity_metadata(&mut tx, &identity.id, &challenge.phone_e164, now, now)
            .await?;

        let session = public::create_session_in_tx_with_policy(
            &mut tx,
            &identity.user_id,
            session_id,
            public::new_session_token(),
            now,
            expires_at,
            SessionCreateOptions { device_id, client },
            self.session_policy.as_ref(),
        )
        .await?;

        tx.commit().await.map_err(map_sql_error)?;
        Ok(Some(session))
    }

    pub async fn set_password(&self, input: SetPhonePasswordOptions<'_>) -> AppResult<bool> {
        let SetPhonePasswordOptions {
            user_id,
            password,
            now,
            config,
        } = input;

        let password_hash = hash_password(password, config)?;
        let Some(identity_id) = sqlx::query_scalar::<_, String>(
            r#"
            select identities.id
            from auth.identities identities
            join auth_phone.identities phone_identities on phone_identities.identity_id = identities.id
            where identities.user_id = $1
              and identities.provider = $2
            limit 1
            "#,
        )
        .bind(&user_id.0)
        .bind(PHONE_PROVIDER)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?
        else {
            return Ok(false);
        };

        sqlx::query(
            r#"
            insert into auth_phone.password_credentials (
                identity_id,
                password_hash,
                created_at,
                updated_at
            )
            values ($1, $2, $3, $3)
            on conflict (identity_id) do update
            set password_hash = excluded.password_hash,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(identity_id)
        .bind(password_hash)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;

        Ok(true)
    }

    pub async fn login_password_with_options(
        &self,
        input: LoginPhonePasswordOptions<'_>,
    ) -> AppResult<Option<AuthSession>> {
        let LoginPhonePasswordOptions {
            phone,
            password,
            session_id,
            now,
            expires_at,
            config,
            device_id,
            client,
        } = input;

        let phone_e164 = normalize_phone_e164(phone)?;
        validate_password(password, config)?;
        self.ensure_phone_password_login_not_locked(&phone_e164, now)
            .await?;

        let Some(identity) =
            public::find_active_identity(&self.pool, PHONE_PROVIDER, &phone_e164).await?
        else {
            self.record_failed_phone_password_login(&phone_e164, now, &client)
                .await?;
            return Err(invalid_phone_password_credentials());
        };

        let Some(password_hash) = sqlx::query_scalar::<_, String>(
            r#"
            select credentials.password_hash
            from auth_phone.password_credentials credentials
            where credentials.identity_id = $1
            "#,
        )
        .bind(&identity.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?
        else {
            self.record_failed_phone_password_login(&phone_e164, now, &client)
                .await?;
            return Err(invalid_phone_password_credentials());
        };

        if !verify_password(&password_hash, password)? {
            self.record_failed_phone_password_login(&phone_e164, now, &client)
                .await?;
            return Err(invalid_phone_password_credentials());
        }

        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let session = public::create_session_in_tx_with_policy(
            &mut tx,
            &identity.user_id,
            session_id,
            public::new_session_token(),
            now,
            expires_at,
            SessionCreateOptions { device_id, client },
            self.session_policy.as_ref(),
        )
        .await?;
        clear_phone_password_login_failures(&mut tx, &phone_e164).await?;
        tx.commit().await.map_err(map_sql_error)?;

        Ok(Some(session))
    }
}

type OtpChallengeRow = (
    String,
    String,
    String,
    String,
    i32,
    i32,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

async fn increment_otp_attempts(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"
        update auth_phone.otp_challenges
        set attempts = attempts + 1
        where id = $1
        "#,
    )
    .bind(challenge_id)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(())
}

async fn find_active_phone_identity_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    phone_e164: &str,
) -> AppResult<Option<public::AuthIdentity>> {
    sqlx::query_as::<_, IdentityRow>(
        r#"
        select identities.id, identities.user_id
        from auth.identities identities
        join auth.users users on users.id = identities.user_id
        where identities.provider = $1
          and identities.provider_subject = $2
          and (users.disabled_at is null or users.disabled_until <= now())
        limit 1
        "#,
    )
    .bind(PHONE_PROVIDER)
    .bind(phone_e164)
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.map(identity_from_row))
    .map_err(map_sql_error)
}

async fn upsert_phone_identity_metadata(
    tx: &mut Transaction<'_, Postgres>,
    identity_id: &str,
    phone_e164: &str,
    verified_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        r#"
        insert into auth_phone.identities (
            identity_id,
            provider,
            phone_e164,
            verified_at,
            created_at,
            updated_at
        )
        values ($1, $2, $3, $4, $5, $4)
        on conflict (identity_id) do update
        set provider = excluded.provider,
            phone_e164 = excluded.phone_e164,
            verified_at = excluded.verified_at,
            updated_at = excluded.updated_at
        "#,
    )
    .bind(identity_id)
    .bind(PHONE_PROVIDER)
    .bind(phone_e164)
    .bind(verified_at)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(())
}

async fn clear_phone_password_login_failures(
    tx: &mut Transaction<'_, Postgres>,
    phone_e164: &str,
) -> AppResult<()> {
    sqlx::query(
        r#"
        delete from auth_phone.password_failures
        where phone_e164 = $1
        "#,
    )
    .bind(phone_e164)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(())
}

impl PhoneOtpPurpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::PasswordSetup => "password_setup",
            Self::PasswordReset => "password_reset",
        }
    }

    fn from_db(value: &str) -> AppResult<Self> {
        match value {
            "sign_in" => Ok(Self::SignIn),
            "password_setup" => Ok(Self::PasswordSetup),
            "password_reset" => Ok(Self::PasswordReset),
            _ => Err(AppError::new(
                ErrorCode::Internal,
                format!("Unknown phone OTP purpose: {value}"),
            )),
        }
    }
}

type IdentityRow = (String, String);

fn identity_from_row(row: IdentityRow) -> public::AuthIdentity {
    let (id, user_id) = row;
    public::AuthIdentity {
        id,
        user_id: AuthUserId(user_id),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FailedPhonePasswordLoginUpdate {
    failed_count: i32,
    window_started_at: DateTime<Utc>,
    locked_until: Option<DateTime<Utc>>,
}

fn failed_phone_password_login_update(
    failed_count: i32,
    window_started_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> FailedPhonePasswordLoginUpdate {
    if now - window_started_at > PASSWORD_LOGIN_FAILURE_WINDOW {
        return FailedPhonePasswordLoginUpdate {
            failed_count: 1,
            window_started_at: now,
            locked_until: None,
        };
    }

    let failed_count = failed_count + 1;
    FailedPhonePasswordLoginUpdate {
        failed_count,
        window_started_at,
        locked_until: (failed_count >= MAX_FAILED_PASSWORD_LOGINS)
            .then_some(now + PASSWORD_LOGIN_LOCKOUT_DURATION),
    }
}

fn invalid_phone_password_credentials() -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Invalid phone or password")
}

fn phone_password_rate_limited(locked_until: DateTime<Utc>) -> AppError {
    AppError::new(
        ErrorCode::RateLimited,
        format!(
            "Too many phone password login attempts; try again after {}",
            locked_until.to_rfc3339()
        ),
    )
}

impl PhoneAuthRepository {
    async fn ensure_phone_password_login_not_locked(
        &self,
        phone_e164: &str,
        now: DateTime<Utc>,
    ) -> AppResult<()> {
        let locked_until = sqlx::query_scalar::<_, DateTime<Utc>>(
            r#"
            select locked_until
            from auth_phone.password_failures
            where phone_e164 = $1 and locked_until > $2
            "#,
        )
        .bind(phone_e164)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sql_error)?;

        match locked_until {
            Some(locked_until) => Err(phone_password_rate_limited(locked_until)),
            None => Ok(()),
        }
    }

    async fn record_failed_phone_password_login(
        &self,
        phone_e164: &str,
        now: DateTime<Utc>,
        client: &ClientRequestMetadata,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let row = sqlx::query_as::<_, (i32, DateTime<Utc>)>(
            r#"
            select failed_count, window_started_at
            from auth_phone.password_failures
            where phone_e164 = $1
            for update
            "#,
        )
        .bind(phone_e164)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sql_error)?;

        if let Some((failed_count, window_started_at)) = row {
            let update = failed_phone_password_login_update(failed_count, window_started_at, now);
            sqlx::query(
                r#"
                update auth_phone.password_failures
                set failed_count = $2,
                    window_started_at = $3,
                    last_failed_at = $4,
                    locked_until = $5,
                    last_failed_ip = $6,
                    last_failed_user_agent = $7
                where phone_e164 = $1
                "#,
            )
            .bind(phone_e164)
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
                insert into auth_phone.password_failures (
                    phone_e164,
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
            .bind(phone_e164)
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
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_phone_password_login_update_locks_on_fifth_failure_in_window() {
        let now = Utc::now();
        let update = failed_phone_password_login_update(4, now - Duration::minutes(1), now);

        assert_eq!(update.failed_count, 5);
        assert_eq!(update.window_started_at, now - Duration::minutes(1));
        assert_eq!(
            update.locked_until,
            Some(now + PASSWORD_LOGIN_LOCKOUT_DURATION)
        );
    }
}
