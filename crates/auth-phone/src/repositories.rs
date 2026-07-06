use crate::config::AuthPhoneConfig;
use crate::otp::{hash_otp_code, new_otp_code};
use crate::phone::normalize_phone_e164;
use auth::session_policy::{AllowSessionPolicy, AuthSessionPolicy};
use chrono::{DateTime, Duration, Utc};
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};
use sqlx::{Postgres, Transaction};
use std::sync::Arc;

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

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}
