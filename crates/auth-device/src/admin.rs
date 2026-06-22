use crate::repositories::{AuthDevice, PostgresAuthDeviceRepository};
use platform_core::{AppError, AppResult, ErrorCode};
use platform_module::{AdminDataSource, AdminListQuery, AdminPage};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug)]
pub struct AuthDeviceAdminData {
    repository: Arc<PostgresAuthDeviceRepository>,
}

impl AuthDeviceAdminData {
    #[must_use]
    pub fn new(repository: Arc<PostgresAuthDeviceRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait::async_trait]
impl AdminDataSource for AuthDeviceAdminData {
    async fn list(&self, entity: &str, query: &AdminListQuery) -> AppResult<AdminPage> {
        match entity {
            "devices" => {
                let rows = self
                    .repository
                    .list(query.limit.saturating_add(1), query.cursor.as_deref())
                    .await?;
                let has_more = rows.len() as i64 > query.limit.max(0);
                let take = rows.len().min(query.limit.max(0) as usize);
                let page_rows = &rows[..take];
                let next_cursor = has_more
                    .then(|| page_rows.last().map(|device| device.id.clone()))
                    .flatten();
                Ok(AdminPage {
                    records: page_rows.iter().map(device_to_value).collect(),
                    next_cursor,
                })
            }
            other => Err(unknown_entity(other)),
        }
    }

    async fn get(&self, entity: &str, id: &str) -> AppResult<Option<Value>> {
        match entity {
            "devices" => Ok(self
                .repository
                .find_by_id(id)
                .await?
                .as_ref()
                .map(device_to_value)),
            other => Err(unknown_entity(other)),
        }
    }
}

fn device_to_value(device: &AuthDevice) -> Value {
    serde_json::json!({
        "id": device.id,
        "user_id": device.user_id.0,
        "created_at": device.created_at,
        "updated_at": device.updated_at,
        "trusted_at": device.trusted_at,
        "primary_at": device.primary_at,
        "last_seen_ip": device.last_seen_ip,
        "last_seen_user_agent": device.last_seen_user_agent,
    })
}

fn unknown_entity(entity: &str) -> AppError {
    AppError::new(
        ErrorCode::NotFound,
        format!("unknown admin entity: {entity}"),
    )
}
