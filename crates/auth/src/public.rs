use crate::resolver::session_token_hash;
use crate::session_policy::{AllowSessionPolicy, AuthSessionPolicy, SessionCreateInput};
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, DbPool, ErrorCode};
use sqlx::{Postgres, Transaction};
use std::fmt::Write as _;

pub use crate::models::{AuthSession, AuthUserId};
pub use crate::session_policy::SessionCreateOptions;

pub fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness should be available");

    let mut token = String::with_capacity("sess_".len() + bytes.len() * 2);
    token.push_str("sess_");
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity {
    pub id: String,
    pub user_id: AuthUserId,
}

pub async fn create_user_identity_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: AuthUserId,
    identity_id: String,
    provider: &str,
    provider_subject: &str,
    created_at: DateTime<Utc>,
) -> AppResult<AuthIdentity> {
    create_user_identity_in_tx_with_anonymous(
        tx,
        user_id,
        identity_id,
        provider,
        provider_subject,
        created_at,
        false,
    )
    .await
}

pub async fn create_anonymous_user_identity_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: AuthUserId,
    identity_id: String,
    provider: &str,
    provider_subject: &str,
    created_at: DateTime<Utc>,
) -> AppResult<AuthIdentity> {
    create_user_identity_in_tx_with_anonymous(
        tx,
        user_id,
        identity_id,
        provider,
        provider_subject,
        created_at,
        true,
    )
    .await
}

pub async fn link_identity_to_anonymous_user_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &AuthUserId,
    identity_id: String,
    provider: &str,
    provider_subject: &str,
    created_at: DateTime<Utc>,
) -> AppResult<AuthIdentity> {
    let anonymous_user_exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth.users
            where id = $1
              and is_anonymous
              and (disabled_at is null or disabled_until <= now())
        )
        "#,
    )
    .bind(&user_id.0)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    if !anonymous_user_exists {
        return Err(AppError::new(
            ErrorCode::Conflict,
            "Auth user is not anonymous",
        ));
    }

    sqlx::query(
        r#"
        insert into auth.identities (id, user_id, provider, provider_subject, created_at, updated_at)
        values ($1, $2, $3, $4, $5, $5)
        "#,
    )
    .bind(&identity_id)
    .bind(&user_id.0)
    .bind(provider)
    .bind(provider_subject)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    sqlx::query(
        r#"
        update auth.users
        set is_anonymous = false
        where id = $1
        "#,
    )
    .bind(&user_id.0)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(AuthIdentity {
        id: identity_id,
        user_id: user_id.clone(),
    })
}

async fn create_user_identity_in_tx_with_anonymous(
    tx: &mut Transaction<'_, Postgres>,
    user_id: AuthUserId,
    identity_id: String,
    provider: &str,
    provider_subject: &str,
    created_at: DateTime<Utc>,
    is_anonymous: bool,
) -> AppResult<AuthIdentity> {
    sqlx::query(
        r#"
        insert into auth.users (
            id,
            is_anonymous,
            created_at,
            disabled_at,
            disabled_reason,
            disabled_until
        )
        values ($1, $2, $3, null, null, null)
        "#,
    )
    .bind(&user_id.0)
    .bind(is_anonymous)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    sqlx::query(
        r#"
        insert into auth.identities (id, user_id, provider, provider_subject, created_at, updated_at)
        values ($1, $2, $3, $4, $5, $5)
        "#,
    )
    .bind(&identity_id)
    .bind(&user_id.0)
    .bind(provider)
    .bind(provider_subject)
    .bind(created_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(AuthIdentity {
        id: identity_id,
        user_id,
    })
}

pub async fn find_active_identity(
    pool: &DbPool,
    provider: &str,
    provider_subject: &str,
) -> AppResult<Option<AuthIdentity>> {
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
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(identity_from_row))
    .map_err(map_sql_error)
}

pub async fn create_session(
    pool: &DbPool,
    user_id: &AuthUserId,
    session_id: String,
    token: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> AppResult<AuthSession> {
    create_session_with_policy(
        pool,
        user_id,
        session_id,
        token,
        created_at,
        expires_at,
        SessionCreateOptions::default(),
        &AllowSessionPolicy,
    )
    .await
}

pub async fn create_session_with_policy(
    pool: &DbPool,
    user_id: &AuthUserId,
    session_id: String,
    token: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    options: SessionCreateOptions,
    policy: &dyn AuthSessionPolicy,
) -> AppResult<AuthSession> {
    let mut tx = pool.begin().await.map_err(map_sql_error)?;
    let session = create_session_in_tx_with_policy(
        &mut tx, user_id, session_id, token, created_at, expires_at, options, policy,
    )
    .await?;
    tx.commit().await.map_err(map_sql_error)?;
    Ok(session)
}

pub async fn create_session_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &AuthUserId,
    session_id: String,
    token: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> AppResult<AuthSession> {
    create_session_in_tx_with_policy(
        tx,
        user_id,
        session_id,
        token,
        created_at,
        expires_at,
        SessionCreateOptions::default(),
        &AllowSessionPolicy,
    )
    .await
}

pub async fn create_session_in_tx_with_policy(
    tx: &mut Transaction<'_, Postgres>,
    user_id: &AuthUserId,
    session_id: String,
    token: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    options: SessionCreateOptions,
    policy: &dyn AuthSessionPolicy,
) -> AppResult<AuthSession> {
    let active_user_exists = sqlx::query_scalar::<_, bool>(
        r#"
        select exists(
            select 1
            from auth.users
            where id = $1
              and (disabled_at is null or disabled_until <= now())
        )
        "#,
    )
    .bind(&user_id.0)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    if !active_user_exists {
        return Err(AppError::new(ErrorCode::Forbidden, "Auth user is disabled"));
    }

    let decision = policy
        .before_session_create(&SessionCreateInput {
            user_id: user_id.clone(),
            session_id: session_id.clone(),
            proposed_device_id: options.device_id,
            created_at,
            expires_at,
            client: options.client.clone(),
        })
        .await?;

    sqlx::query(
        r#"
        insert into auth.sessions (
            id,
            user_id,
            token_hash,
            device_id,
            client_ip,
            user_agent,
            created_at,
            expires_at,
            revoked_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, null)
        "#,
    )
    .bind(&session_id)
    .bind(&user_id.0)
    .bind(session_token_hash(&token))
    .bind(decision.device_id.as_deref())
    .bind(options.client.ip.as_deref())
    .bind(options.client.user_agent.as_deref())
    .bind(created_at)
    .bind(expires_at)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;

    Ok(AuthSession {
        id: session_id,
        user_id: user_id.clone(),
        token,
        device_id: decision.device_id,
        expires_at,
    })
}

type IdentityRow = (String, String);

fn identity_from_row(row: IdentityRow) -> AuthIdentity {
    let (id, user_id) = row;
    AuthIdentity {
        id,
        user_id: AuthUserId(user_id),
    }
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(database_error) = &source {
        if database_error.constraint() == Some("identities_provider_subject_key") {
            return AppError::new(ErrorCode::Conflict, "An auth identity already exists")
                .with_source(source);
        }
    }

    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}
