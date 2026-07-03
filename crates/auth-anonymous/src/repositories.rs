use auth::public::{self, AuthSession, AuthUserId, SessionCreateOptions};
use auth::session_policy::{AllowSessionPolicy, AuthSessionPolicy};
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};
use std::sync::Arc;

pub const ANONYMOUS_PROVIDER: &str = "anonymous";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnonymousSessionOptions {
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
}

#[derive(Debug, Clone)]
pub struct AnonymousAuthRepository {
    pool: DbPool,
    session_policy: Arc<dyn AuthSessionPolicy>,
}

impl AnonymousAuthRepository {
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

    pub async fn sign_in(
        &self,
        user_id: String,
        identity_id: String,
        session_id: String,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        options: AnonymousSessionOptions,
    ) -> AppResult<AuthSession> {
        let token = public::new_session_token();
        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let identity = public::create_anonymous_user_identity_in_tx(
            &mut tx,
            AuthUserId(user_id),
            identity_id.clone(),
            ANONYMOUS_PROVIDER,
            &identity_id,
            now,
        )
        .await?;
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
        Ok(session)
    }
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}
