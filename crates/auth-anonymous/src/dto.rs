use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct AnonymousSignInRequest {
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnonymousSessionResponse {
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub is_anonymous: bool,
}
