use platform_core::{AppContext, AppError, AppResult};
use serde::Deserialize;

pub const CONFIG_PREFIX: &str = "auth-google";

const DEFAULT_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const DEFAULT_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const DEFAULT_SCOPE: &str = "openid profile email";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GoogleAuthConfig {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub authorize_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub userinfo_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGoogleAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<String>,
    pub scope: String,
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

impl GoogleAuthConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        ctx.config.module_local_config(CONFIG_PREFIX)
    }

    pub fn resolve(&self) -> AppResult<ResolvedGoogleAuthConfig> {
        Ok(ResolvedGoogleAuthConfig {
            client_id: required(&self.client_id, "client_id")?,
            client_secret: required(&self.client_secret, "client_secret")?,
            redirect_uri: optional_trimmed(&self.redirect_uri),
            scope: optional_trimmed(&self.scope).unwrap_or_else(|| DEFAULT_SCOPE.to_owned()),
            authorize_url: optional_trimmed(&self.authorize_url)
                .unwrap_or_else(|| DEFAULT_AUTHORIZE_URL.to_owned()),
            token_url: optional_trimmed(&self.token_url)
                .unwrap_or_else(|| DEFAULT_TOKEN_URL.to_owned()),
            userinfo_url: optional_trimmed(&self.userinfo_url)
                .unwrap_or_else(|| DEFAULT_USERINFO_URL.to_owned()),
        })
    }
}

impl Default for GoogleAuthConfig {
    fn default() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            authorize_url: None,
            token_url: None,
            userinfo_url: None,
        }
    }
}

fn optional_trimmed(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn required(value: &Option<String>, field: &str) -> AppResult<String> {
    optional_trimmed(value).ok_or_else(|| config_error(field, &format!("{field} is required")))
}

fn config_error(field: &str, reason: &str) -> AppError {
    AppError::validation(
        "Invalid Google auth provider configuration",
        vec![platform_core::error::ErrorDetail {
            field: Some(field.to_owned()),
            reason: reason.to_owned(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_requires_client_id_and_secret() {
        assert!(GoogleAuthConfig::default().resolve().is_err());

        let config = GoogleAuthConfig {
            client_id: Some("google-client".to_owned()),
            client_secret: Some("google-secret".to_owned()),
            redirect_uri: Some(" https://app.example.com/v1/auth/google/callback ".to_owned()),
            ..GoogleAuthConfig::default()
        };
        let resolved = config.resolve().expect("valid Google config");

        assert_eq!(resolved.client_id, "google-client");
        assert_eq!(resolved.client_secret, "google-secret");
        assert_eq!(
            resolved.redirect_uri.as_deref(),
            Some("https://app.example.com/v1/auth/google/callback")
        );
        assert_eq!(resolved.scope, DEFAULT_SCOPE);
        assert_eq!(resolved.authorize_url, DEFAULT_AUTHORIZE_URL);
        assert_eq!(resolved.token_url, DEFAULT_TOKEN_URL);
        assert_eq!(resolved.userinfo_url, DEFAULT_USERINFO_URL);
    }
}
