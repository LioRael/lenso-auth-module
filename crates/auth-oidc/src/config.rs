use platform_core::{AppContext, AppError, AppResult};
use serde::Deserialize;
use serde_json::Value;

pub const CONFIG_PREFIX: &str = "auth-oidc";

const DEFAULT_CONSOLE_CLIENT_ID: &str = "lenso-console";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct OidcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub console_client_id: Option<String>,
    #[serde(default)]
    pub console_redirect_uris: Vec<String>,
    #[serde(default)]
    pub jwks: Option<Value>,
    #[serde(default)]
    pub id_token_private_key_pem: Option<String>,
    #[serde(default)]
    pub id_token_key_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedOidcConfig {
    pub console_client_id: String,
    pub console_redirect_uris: Vec<String>,
    pub issuer: String,
    pub jwks: Value,
    pub id_token_private_key_pem: String,
    pub id_token_key_id: Option<String>,
}

impl OidcConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        ctx.config.module_local_config(CONFIG_PREFIX)
    }

    pub fn resolve(&self) -> AppResult<Option<ResolvedOidcConfig>> {
        if !self.enabled {
            return Ok(None);
        }

        let issuer = self
            .issuer
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| config_error("issuer", "issuer is required"))?
            .trim_end_matches('/')
            .to_owned();
        let jwks = self
            .jwks
            .clone()
            .filter(|value| value.get("keys").and_then(Value::as_array).is_some())
            .ok_or_else(|| config_error("jwks", "jwks must contain a keys array"))?;
        let id_token_private_key_pem = self
            .id_token_private_key_pem
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                config_error(
                    "id_token_private_key_pem",
                    "id_token_private_key_pem is required",
                )
            })?
            .to_owned();
        let id_token_key_id = self
            .id_token_key_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let console_redirect_uris = self
            .console_redirect_uris
            .iter()
            .map(|uri| uri.trim())
            .filter(|uri| !uri.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if console_redirect_uris.is_empty()
            || console_redirect_uris.iter().any(|uri| uri.contains('#'))
        {
            return Err(config_error(
                "console_redirect_uris",
                "console_redirect_uris must contain at least one redirect URI without a fragment",
            ));
        }

        Ok(Some(ResolvedOidcConfig {
            console_client_id: self
                .console_client_id
                .clone()
                .unwrap_or_else(|| DEFAULT_CONSOLE_CLIENT_ID.to_owned()),
            console_redirect_uris,
            issuer,
            jwks,
            id_token_private_key_pem,
            id_token_key_id,
        }))
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            console_client_id: None,
            console_redirect_uris: Vec::new(),
            jwks: None,
            id_token_private_key_pem: None,
            id_token_key_id: None,
        }
    }
}

fn config_error(field: &str, reason: &str) -> AppError {
    AppError::validation(
        "Invalid OIDC provider configuration",
        vec![platform_core::error::ErrorDetail {
            field: Some(field.to_owned()),
            reason: reason.to_owned(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_returns_none_when_disabled() {
        assert!(OidcConfig::default().resolve().unwrap().is_none());
    }

    #[test]
    fn resolve_requires_issuer_jwks_and_redirect_uris() {
        let config = OidcConfig {
            enabled: true,
            ..OidcConfig::default()
        };

        assert!(config.resolve().is_err());

        let config = OidcConfig {
            enabled: true,
            issuer: Some("https://example.com/".to_owned()),
            console_redirect_uris: vec!["https://console.example.com/callback".to_owned()],
            jwks: Some(json!({"keys": []})),
            id_token_private_key_pem: Some("test-private-key".to_owned()),
            ..OidcConfig::default()
        };
        let oidc = config.resolve().expect("valid config").unwrap();

        assert_eq!(oidc.issuer, "https://example.com");
        assert_eq!(oidc.console_client_id, "lenso-console");
        assert_eq!(
            oidc.console_redirect_uris,
            vec!["https://console.example.com/callback".to_owned()]
        );
    }
}
