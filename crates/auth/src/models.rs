use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct AuthUserId(pub String);

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthUser {
    pub id: AuthUserId,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub disabled_reason: Option<String>,
    pub disabled_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthSession {
    pub id: String,
    pub user_id: AuthUserId,
    pub token: String,
    pub device_id: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthSessionRecord {
    pub id: String,
    pub user_id: AuthUserId,
    pub device_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
