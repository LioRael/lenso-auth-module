use auth::public::{self, AuthIdentity, AuthUserId};
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, DbPool, ErrorCode};

pub const GITHUB_PROVIDER: &str = "github";

#[derive(Debug, Clone)]
pub struct GitHubAuthRepository {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubIdentityInput {
    pub github_user_id: String,
    pub login: String,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub user_id: String,
    pub identity_id: String,
    pub now: DateTime<Utc>,
}

impl GitHubAuthRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn find_or_create_identity(
        &self,
        input: GitHubIdentityInput,
    ) -> AppResult<AuthIdentity> {
        if let Some(identity) =
            public::find_active_identity(&self.pool, GITHUB_PROVIDER, &input.github_user_id).await?
        {
            self.upsert_account(&identity.id, &input).await?;
            return Ok(identity);
        }

        let mut tx = self.pool.begin().await.map_err(map_sql_error)?;
        let identity = public::create_user_identity_in_tx(
            &mut tx,
            AuthUserId(input.user_id.clone()),
            input.identity_id.clone(),
            GITHUB_PROVIDER,
            &input.github_user_id,
            input.now,
        )
        .await?;
        upsert_account_in_tx(&mut tx, &identity.id, &input).await?;
        tx.commit().await.map_err(map_sql_error)?;
        Ok(identity)
    }

    async fn upsert_account(
        &self,
        identity_id: &str,
        input: &GitHubIdentityInput,
    ) -> AppResult<()> {
        sqlx::query(
            r#"
            insert into auth_github.accounts (
                identity_id,
                github_user_id,
                login,
                email,
                avatar_url,
                updated_at
            )
            values ($1, $2, $3, $4, $5, $6)
            on conflict (identity_id) do update
            set github_user_id = excluded.github_user_id,
                login = excluded.login,
                email = excluded.email,
                avatar_url = excluded.avatar_url,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(identity_id)
        .bind(&input.github_user_id)
        .bind(&input.login)
        .bind(input.email.as_deref())
        .bind(input.avatar_url.as_deref())
        .bind(input.now)
        .execute(&self.pool)
        .await
        .map_err(map_sql_error)?;
        Ok(())
    }
}

async fn upsert_account_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    identity_id: &str,
    input: &GitHubIdentityInput,
) -> AppResult<()> {
    sqlx::query(
        r#"
        insert into auth_github.accounts (
            identity_id,
            github_user_id,
            login,
            email,
            avatar_url,
            updated_at
        )
        values ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(identity_id)
    .bind(&input.github_user_id)
    .bind(&input.login)
    .bind(input.email.as_deref())
    .bind(input.avatar_url.as_deref())
    .bind(input.now)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error)?;
    Ok(())
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}
