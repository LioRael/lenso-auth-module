use auth::models::AuthUserId;
use chrono::{DateTime, Utc};
use platform_core::{AppError, AppResult, ClientRequestMetadata, DbPool, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDevice {
    pub id: String,
    pub user_id: AuthUserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub primary_at: Option<DateTime<Utc>>,
    pub last_seen_ip: Option<String>,
    pub last_seen_user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PostgresAuthDeviceRepository {
    pool: DbPool,
}

impl PostgresAuthDeviceRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn upsert_seen_device(
        &self,
        user_id: &AuthUserId,
        device_id: &str,
        seen_at: DateTime<Utc>,
        client: &ClientRequestMetadata,
    ) -> AppResult<AuthDevice> {
        sqlx::query_as::<_, DeviceRow>(
            r#"
            insert into auth_device.devices (
                id,
                user_id,
                created_at,
                updated_at,
                trusted_at,
                primary_at,
                last_seen_ip,
                last_seen_user_agent
            )
            values ($1, $2, $3, $3, null, null, $4, $5)
            on conflict (id) do update
            set user_id = excluded.user_id,
                updated_at = excluded.updated_at,
                last_seen_ip = excluded.last_seen_ip,
                last_seen_user_agent = excluded.last_seen_user_agent
            returning id, user_id, created_at, updated_at, trusted_at, primary_at, last_seen_ip, last_seen_user_agent
            "#,
        )
        .bind(device_id)
        .bind(&user_id.0)
        .bind(seen_at)
        .bind(client.ip.as_deref())
        .bind(client.user_agent.as_deref())
        .fetch_one(&self.pool)
        .await
        .map(device_from_row)
        .map_err(map_sql_error)
    }

    pub async fn list(&self, limit: i64, cursor: Option<&str>) -> AppResult<Vec<AuthDevice>> {
        let rows = match cursor {
            Some(after) => {
                sqlx::query_as::<_, DeviceRow>(
                    r#"
                    select id, user_id, created_at, updated_at, trusted_at, primary_at, last_seen_ip, last_seen_user_agent
                    from auth_device.devices
                    where id > $1
                    order by id asc
                    limit $2
                    "#,
                )
                .bind(after)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, DeviceRow>(
                    r#"
                    select id, user_id, created_at, updated_at, trusted_at, primary_at, last_seen_ip, last_seen_user_agent
                    from auth_device.devices
                    order by id asc
                    limit $1
                    "#,
                )
                .bind(limit)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(map_sql_error)?;

        Ok(rows.into_iter().map(device_from_row).collect())
    }

    pub async fn find_by_id(&self, device_id: &str) -> AppResult<Option<AuthDevice>> {
        sqlx::query_as::<_, DeviceRow>(
            r#"
            select id, user_id, created_at, updated_at, trusted_at, primary_at, last_seen_ip, last_seen_user_agent
            from auth_device.devices
            where id = $1
            "#,
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(device_from_row))
        .map_err(map_sql_error)
    }
}

type DeviceRow = (
    String,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<String>,
);

fn device_from_row(row: DeviceRow) -> AuthDevice {
    let (
        id,
        user_id,
        created_at,
        updated_at,
        trusted_at,
        primary_at,
        last_seen_ip,
        last_seen_user_agent,
    ) = row;
    AuthDevice {
        id,
        user_id: AuthUserId(user_id),
        created_at,
        updated_at,
        trusted_at,
        primary_at,
        last_seen_ip,
        last_seen_user_agent,
    }
}

fn map_sql_error(source: sqlx::Error) -> AppError {
    AppError::new(ErrorCode::Internal, "Internal server error").with_source(source)
}
