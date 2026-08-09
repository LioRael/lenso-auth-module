use platform_core::{
    AppContext, RuntimeConfigDescriptor, RuntimeConfigScope, RuntimeConfigSnapshot,
    RuntimeConfigType,
};
use std::sync::LazyLock;
use std::time::Duration;

const SESSION_CACHE_KEY: &str = "auth.session_cache";

pub const SESSION_CACHE_MAX_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCacheMode {
    Database,
    Redis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRuntimeConfig {
    pub session_cache: SessionCacheMode,
}

impl AuthRuntimeConfig {
    #[must_use]
    pub fn from_context(ctx: &AppContext) -> Self {
        Self::from_snapshot(&ctx.runtime_config.snapshot())
    }

    #[must_use]
    pub fn from_snapshot(snapshot: &RuntimeConfigSnapshot) -> Self {
        let session_cache = snapshot
            .raw(SESSION_CACHE_KEY)
            .and_then(serde_json::Value::as_str)
            .and_then(SessionCacheMode::from_value)
            .unwrap_or(SessionCacheMode::Database);
        Self { session_cache }
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

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{RuntimeConfigRegistry, RuntimeConfigSnapshot};
    use std::collections::BTreeMap;

    #[test]
    fn defaults_to_database_cache() {
        let registry = RuntimeConfigRegistry::try_new(RUNTIME_CONFIG.clone()).unwrap();
        let snapshot = RuntimeConfigSnapshot::resolve(&registry, "api", &BTreeMap::new());

        let config = AuthRuntimeConfig::from_snapshot(&snapshot);

        assert_eq!(config.session_cache, SessionCacheMode::Database);
    }
}
