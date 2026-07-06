use platform_core::{AppContext, AppResult, RuntimeConfigDescriptor, RuntimeConfigGroupDescriptor};
use serde::Deserialize;
use std::sync::LazyLock;

pub const CONFIG_PREFIX: &str = "auth-phone";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthPhoneConfig {
    #[serde(default = "default_otp_code_length")]
    pub otp_code_length: usize,
    #[serde(default = "default_otp_ttl_seconds")]
    pub otp_ttl_seconds: i64,
    #[serde(default = "default_otp_resend_cooldown_seconds")]
    pub otp_resend_cooldown_seconds: i64,
    #[serde(default = "default_otp_max_attempts")]
    pub otp_max_attempts: i32,
    #[serde(default = "default_otp_secret")]
    pub otp_secret: String,
    #[serde(default)]
    pub return_debug_otp_code: bool,
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
}

impl Default for AuthPhoneConfig {
    fn default() -> Self {
        Self {
            otp_code_length: default_otp_code_length(),
            otp_ttl_seconds: default_otp_ttl_seconds(),
            otp_resend_cooldown_seconds: default_otp_resend_cooldown_seconds(),
            otp_max_attempts: default_otp_max_attempts(),
            otp_secret: default_otp_secret(),
            return_debug_otp_code: false,
            password_min_length: default_password_min_length(),
        }
    }
}

impl AuthPhoneConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        ctx.runtime_config.snapshot().get(CONFIG_PREFIX)
    }
}

pub static RUNTIME_CONFIG_GROUPS: LazyLock<Vec<RuntimeConfigGroupDescriptor>> =
    LazyLock::new(Vec::new);

pub static RUNTIME_CONFIG: LazyLock<Vec<RuntimeConfigDescriptor>> = LazyLock::new(Vec::new);

fn default_otp_code_length() -> usize {
    6
}

fn default_otp_ttl_seconds() -> i64 {
    300
}

fn default_otp_resend_cooldown_seconds() -> i64 {
    60
}

fn default_otp_max_attempts() -> i32 {
    5
}

fn default_otp_secret() -> String {
    "local-development-auth-phone-otp-secret".to_owned()
}

fn default_password_min_length() -> usize {
    8
}
