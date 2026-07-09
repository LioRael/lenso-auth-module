use platform_core::{
    AppContext, RuntimeConfigDescriptor, RuntimeConfigScope, RuntimeConfigSnapshot,
    RuntimeConfigType,
};
use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::Duration;

const SESSION_CACHE_KEY: &str = "auth.session_cache";
const CONSOLE_ADMIN_USER_SCOPES_KEY: &str = "auth.console_admin_user_scopes";

pub const SESSION_CACHE_MAX_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCacheMode {
    Database,
    Redis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRuntimeConfig {
    pub session_cache: SessionCacheMode,
    pub console_admin_user_scopes: BTreeMap<String, Vec<String>>,
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
        let console_admin_user_scopes = snapshot
            .raw(CONSOLE_ADMIN_USER_SCOPES_KEY)
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default();

        Self {
            session_cache,
            console_admin_user_scopes,
        }
    }
}

impl Default for AuthRuntimeConfig {
    fn default() -> Self {
        Self {
            session_cache: SessionCacheMode::Database,
            console_admin_user_scopes: BTreeMap::new(),
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
    vec![
        RuntimeConfigDescriptor {
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
        },
        RuntimeConfigDescriptor {
            key: CONSOLE_ADMIN_USER_SCOPES_KEY.to_owned(),
            scope: RuntimeConfigScope::Shared,
            group: None,
            section: None,
            order: 20,
            visible_when: None,
            generated: None,
            value_type: RuntimeConfigType::Json,
            default: serde_json::json!({}),
            editable: true,
            restart_only: true,
            description: "Map of auth user ids to Console admin scopes. Users must include `console.admin` to enter admin HTTP endpoints.",
        },
    ]
});

#[cfg(test)]
mod tests {
    use super::*;
    use platform_core::{RuntimeConfigRegistry, RuntimeConfigSnapshot};
    use serde_json::json;

    #[test]
    fn defaults_to_database_cache_and_empty_console_admin_scopes() {
        let registry = RuntimeConfigRegistry::try_new(RUNTIME_CONFIG.clone()).unwrap();
        let snapshot = RuntimeConfigSnapshot::resolve(&registry, "api", &BTreeMap::new());

        let config = AuthRuntimeConfig::from_snapshot(&snapshot);

        assert_eq!(config.session_cache, SessionCacheMode::Database);
        assert!(config.console_admin_user_scopes.is_empty());
    }

    #[test]
    fn reads_console_admin_user_scopes_from_runtime_config() {
        let registry = RuntimeConfigRegistry::try_new(RUNTIME_CONFIG.clone()).unwrap();
        let mut stored = BTreeMap::new();
        stored.insert(
            ("*".to_owned(), CONSOLE_ADMIN_USER_SCOPES_KEY.to_owned()),
            json!({
                "usr_admin": [
                    "console.admin",
                    "auth.users.read",
                    "auth.users.manage",
                    "auth.sessions.revoke"
                ]
            }),
        );
        let snapshot = RuntimeConfigSnapshot::resolve(&registry, "api", &stored);

        let config = AuthRuntimeConfig::from_snapshot(&snapshot);

        assert_eq!(
            config.console_admin_user_scopes.get("usr_admin"),
            Some(&vec![
                "console.admin".to_owned(),
                "auth.users.read".to_owned(),
                "auth.users.manage".to_owned(),
                "auth.sessions.revoke".to_owned()
            ])
        );
    }
}
