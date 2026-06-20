use platform_core::{AppContext, RuntimeConfigDescriptor, RuntimeConfigScope, RuntimeConfigType};
use std::sync::LazyLock;

const SESSION_CACHE_KEY: &str = "auth.session_cache";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCacheMode {
    Database,
    Redis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRuntimeConfig {
    pub session_cache: SessionCacheMode,
}

impl AuthRuntimeConfig {
    #[must_use]
    pub fn from_context(ctx: &AppContext) -> Self {
        ctx.runtime_config
            .snapshot()
            .raw(SESSION_CACHE_KEY)
            .and_then(serde_json::Value::as_str)
            .and_then(SessionCacheMode::from_value)
            .map_or_else(Self::default, |session_cache| Self { session_cache })
    }
}

impl Default for AuthRuntimeConfig {
    fn default() -> Self {
        Self {
            session_cache: SessionCacheMode::Database,
        }
    }
}

impl SessionCacheMode {
    fn from_value(value: &str) -> Option<Self> {
        match value {
            "database" => Some(Self::Database),
            "redis" => Some(Self::Redis),
            _ => None,
        }
    }
}

pub static RUNTIME_CONFIG: LazyLock<Vec<RuntimeConfigDescriptor>> = LazyLock::new(|| {
    vec![RuntimeConfigDescriptor {
        key: SESSION_CACHE_KEY.to_owned(),
        scope: RuntimeConfigScope::Shared,
        group: None,
        section: None,
        order: 10,
        visible_when: None,
        generated: None,
        value_type: RuntimeConfigType::Enum(&["database", "redis"]),
        default: serde_json::json!("database"),
        editable: true,
        restart_only: true,
        description: "Session cache backend used by auth session resolution.",
    }]
});
