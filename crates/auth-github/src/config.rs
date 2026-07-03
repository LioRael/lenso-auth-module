use platform_core::{AppContext, AppError, AppResult};
use serde::Deserialize;

pub const CONFIG_PREFIX: &str = "auth-github";

const DEFAULT_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const DEFAULT_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const DEFAULT_API_URL: &str = "https://api.github.com";
const DEFAULT_SCOPE: &str = "read:user user:email";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GitHubAuthConfig {
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
    pub api_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGitHubAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<String>,
    pub scope: String,
    pub authorize_url: String,
    pub token_url: String,
    pub api_url: String,
}

impl GitHubAuthConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        ctx.config.module_local_config(CONFIG_PREFIX)
    }

    pub fn resolve(&self) -> AppResult<ResolvedGitHubAuthConfig> {
        Ok(ResolvedGitHubAuthConfig {
            client_id: required(&self.client_id, "client_id")?,
            client_secret: required(&self.client_secret, "client_secret")?,
            redirect_uri: optional_trimmed(&self.redirect_uri),
            scope: optional_trimmed(&self.scope).unwrap_or_else(|| DEFAULT_SCOPE.to_owned()),
            authorize_url: optional_trimmed(&self.authorize_url)
                .unwrap_or_else(|| DEFAULT_AUTHORIZE_URL.to_owned()),
            token_url: optional_trimmed(&self.token_url)
                .unwrap_or_else(|| DEFAULT_TOKEN_URL.to_owned()),
            api_url: optional_trimmed(&self.api_url).unwrap_or_else(|| DEFAULT_API_URL.to_owned()),
        })
    }
}

impl Default for GitHubAuthConfig {
    fn default() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            scope: None,
            authorize_url: None,
            token_url: None,
            api_url: None,
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
        "Invalid GitHub auth provider configuration",
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
        assert!(GitHubAuthConfig::default().resolve().is_err());

        let config = GitHubAuthConfig {
            client_id: Some("github-client".to_owned()),
            client_secret: Some("github-secret".to_owned()),
            redirect_uri: Some(" https://app.example.com/v1/auth/github/callback ".to_owned()),
            ..GitHubAuthConfig::default()
        };
        let resolved = config.resolve().expect("valid GitHub config");

        assert_eq!(resolved.client_id, "github-client");
        assert_eq!(resolved.client_secret, "github-secret");
        assert_eq!(
            resolved.redirect_uri.as_deref(),
            Some("https://app.example.com/v1/auth/github/callback")
        );
        assert_eq!(resolved.scope, DEFAULT_SCOPE);
        assert_eq!(resolved.authorize_url, DEFAULT_AUTHORIZE_URL);
        assert_eq!(resolved.token_url, DEFAULT_TOKEN_URL);
        assert_eq!(resolved.api_url, DEFAULT_API_URL);
    }
}
