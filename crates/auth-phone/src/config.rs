use platform_core::{
    AppContext, AppResult, RuntimeConfigDescriptor, RuntimeConfigGroupDescriptor,
    RuntimeConfigScope, RuntimeConfigSnapshot, RuntimeConfigType, is_local_development_environment,
};
use serde::Deserialize;
use serde_json::json;
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
        }
    }
}

impl AuthPhoneConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        let mut config = Self::from_snapshot(&ctx.runtime_config.snapshot())?;
        let local_config = ctx.config.module_local_config(CONFIG_PREFIX)?;
        let local_environment = is_local_development_environment(&ctx.config.service.environment);
        config.apply_module_local_config(&local_config, local_environment);
        if !local_environment && config.otp_secret == default_otp_secret() {
            config.otp_secret.clear();
        }
        Ok(config)
    }

    pub fn from_snapshot(snapshot: &RuntimeConfigSnapshot) -> AppResult<Self> {
        snapshot.get(CONFIG_PREFIX)
    }

    fn apply_module_local_config(
        &mut self,
        local_config: &AuthPhoneLocalConfig,
        local_environment: bool,
    ) {
        if let Some(secret) = local_config.otp_secret.as_deref().map(str::trim)
            && !secret.is_empty()
        {
            self.otp_secret = secret.to_owned();
        }
        if local_environment && let Some(return_debug_otp_code) = local_config.return_debug_otp_code
        {
            self.return_debug_otp_code = return_debug_otp_code;
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
struct AuthPhoneLocalConfig {
    #[serde(default)]
    otp_secret: Option<String>,
    #[serde(default)]
    return_debug_otp_code: Option<bool>,
}

pub static RUNTIME_CONFIG_GROUPS: LazyLock<Vec<RuntimeConfigGroupDescriptor>> =
    LazyLock::new(|| {
        vec![RuntimeConfigGroupDescriptor {
            id: "auth-phone.otp",
            label: "Phone OTP",
            description: "Phone OTP code generation, expiry, and verification limits.",
            order: 30,
        }]
    });

pub static RUNTIME_CONFIG: LazyLock<Vec<RuntimeConfigDescriptor>> = LazyLock::new(|| {
    vec![
        RuntimeConfigDescriptor {
            key: "auth-phone.otp_code_length".to_owned(),
            scope: RuntimeConfigScope::Shared,
            group: Some("auth-phone.otp"),
            section: Some("Challenge"),
            order: 10,
            visible_when: None,
            generated: None,
            value_type: RuntimeConfigType::Int {
                min: Some(4),
                max: Some(10),
            },
            default: json!(default_otp_code_length()),
            editable: true,
            restart_only: false,
            description: "Number of numeric digits generated for new phone OTP challenges.",
        },
        RuntimeConfigDescriptor {
            key: "auth-phone.otp_ttl_seconds".to_owned(),
            scope: RuntimeConfigScope::Shared,
            group: Some("auth-phone.otp"),
            section: Some("Challenge"),
            order: 20,
            visible_when: None,
            generated: None,
            value_type: RuntimeConfigType::Int {
                min: Some(60),
                max: Some(3600),
            },
            default: json!(default_otp_ttl_seconds()),
            editable: true,
            restart_only: false,
            description: "Time in seconds before a phone OTP challenge expires.",
        },
        RuntimeConfigDescriptor {
            key: "auth-phone.otp_resend_cooldown_seconds".to_owned(),
            scope: RuntimeConfigScope::Shared,
            group: Some("auth-phone.otp"),
            section: Some("Challenge"),
            order: 30,
            visible_when: None,
            generated: None,
            value_type: RuntimeConfigType::Int {
                min: Some(0),
                max: Some(3600),
            },
            default: json!(default_otp_resend_cooldown_seconds()),
            editable: true,
            restart_only: false,
            description: "Recommended wait time in seconds before requesting another phone OTP.",
        },
        RuntimeConfigDescriptor {
            key: "auth-phone.otp_max_attempts".to_owned(),
            scope: RuntimeConfigScope::Shared,
            group: Some("auth-phone.otp"),
            section: Some("Challenge"),
            order: 40,
            visible_when: None,
            generated: None,
            value_type: RuntimeConfigType::Int {
                min: Some(1),
                max: Some(20),
            },
            default: json!(default_otp_max_attempts()),
            editable: true,
            restart_only: false,
            description: "Maximum verification attempts allowed for a single phone OTP challenge.",
        },
    ]
});

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_contains_auth_phone_keys() {
        let keys: Vec<_> = RUNTIME_CONFIG
            .iter()
            .map(|descriptor| descriptor.key.as_str())
            .collect();

        assert!(keys.contains(&"auth-phone.otp_code_length"));
        assert!(keys.contains(&"auth-phone.otp_ttl_seconds"));
        assert!(!keys.contains(&"auth-phone.otp_secret"));
    }

    #[test]
    fn local_config_overlays_otp_secret_without_runtime_descriptor() {
        let mut config = AuthPhoneConfig::default();
        config.apply_module_local_config(
            &AuthPhoneLocalConfig {
                otp_secret: Some("local-secret".to_owned()),
                return_debug_otp_code: Some(true),
            },
            true,
        );

        assert_eq!(config.otp_secret, "local-secret");
        assert!(config.return_debug_otp_code);
    }

    #[test]
    fn debug_otp_code_local_config_is_ignored_outside_local_environment() {
        let mut config = AuthPhoneConfig::default();
        config.apply_module_local_config(
            &AuthPhoneLocalConfig {
                otp_secret: None,
                return_debug_otp_code: Some(true),
            },
            false,
        );

        assert!(!config.return_debug_otp_code);
    }
}
