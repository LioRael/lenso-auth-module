use crate::repositories::PostgresAuthDeviceRepository;
use auth::session_policy::{AuthSessionPolicy, SessionCreateDecision, SessionCreateInput};
use platform_core::AppResult;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct AuthDevicePolicy {
    repository: Arc<PostgresAuthDeviceRepository>,
}

impl AuthDevicePolicy {
    #[must_use]
    pub fn new(repository: Arc<PostgresAuthDeviceRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait::async_trait]
impl AuthSessionPolicy for AuthDevicePolicy {
    async fn before_session_create(
        &self,
        input: &SessionCreateInput,
    ) -> AppResult<SessionCreateDecision> {
        let Some(device_id) = input
            .proposed_device_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(SessionCreateDecision { device_id: None });
        };
        let device = self
            .repository
            .upsert_seen_device(&input.user_id, device_id, input.created_at)
            .await?;
        Ok(SessionCreateDecision {
            device_id: Some(device.id),
        })
    }
}
