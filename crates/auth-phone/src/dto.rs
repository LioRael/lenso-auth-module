use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhoneOtpStartRequest {
    pub phone: String,
    pub purpose: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhoneOtpStartResponse {
    pub challenge_id: String,
    pub expires_at: DateTime<Utc>,
    pub resend_after: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhoneOtpVerifyRequest {
    pub challenge_id: String,
    pub code: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhonePasswordSetRequest {
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhonePasswordLoginRequest {
    pub phone: String,
    pub password: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhonePasswordUpdatedResponse {
    pub updated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhoneSessionResponse {
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}
