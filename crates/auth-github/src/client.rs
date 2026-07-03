use crate::config::ResolvedGitHubAuthConfig;
use platform_core::{AppError, AppResult, ErrorCode};
use serde::Deserialize;
use std::sync::Arc;

pub type GitHubOAuthClientHandle = Arc<dyn GitHubOAuthClient>;

const GITHUB_REST_API_VERSION: &str = "2026-03-10";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubAccessToken {
    pub access_token: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GitHubUser {
    pub id: i64,
    pub login: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

#[async_trait::async_trait]
pub trait GitHubOAuthClient: std::fmt::Debug + Send + Sync {
    async fn exchange_code(
        &self,
        config: &ResolvedGitHubAuthConfig,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<GitHubAccessToken>;

    async fn load_user(
        &self,
        config: &ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<GitHubUser>;

    async fn load_primary_email(
        &self,
        config: &ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<Option<String>>;
}

#[derive(Debug, Clone)]
pub struct ReqwestGitHubOAuthClient {
    http: reqwest::Client,
}

impl Default for ReqwestGitHubOAuthClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl GitHubOAuthClient for ReqwestGitHubOAuthClient {
    async fn exchange_code(
        &self,
        config: &ResolvedGitHubAuthConfig,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<GitHubAccessToken> {
        let mut body = format!(
            "client_id={}&client_secret={}&code={}&code_verifier={}",
            percent_encode(&config.client_id),
            percent_encode(&config.client_secret),
            percent_encode(code),
            percent_encode(code_verifier)
        );
        if let Some(redirect_uri) = &config.redirect_uri {
            body.push_str("&redirect_uri=");
            body.push_str(&percent_encode(redirect_uri));
        }

        let response = self
            .http
            .post(&config.token_url)
            .header("accept", "application/json")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("user-agent", "lenso-auth-github")
            .body(body)
            .send()
            .await
            .map_err(github_error)?
            .text()
            .await
            .map_err(github_error)?;

        let token: GitHubTokenResponse = serde_json::from_str(&response).map_err(|source| {
            AppError::new(
                ErrorCode::Unauthorized,
                "GitHub OAuth token exchange failed",
            )
            .with_source(source)
        })?;
        if let Some(error) = token.error {
            return Err(AppError::new(
                ErrorCode::Unauthorized,
                token.error_description.unwrap_or(error),
            ));
        }
        let access_token = token.access_token.filter(|value| !value.trim().is_empty());
        access_token
            .map(|access_token| GitHubAccessToken { access_token })
            .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "GitHub did not return a token"))
    }

    async fn load_user(
        &self,
        config: &ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<GitHubUser> {
        let body = self
            .http
            .get(format!("{}/user", config.api_url.trim_end_matches('/')))
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", GITHUB_REST_API_VERSION)
            .header("authorization", format!("Bearer {access_token}"))
            .header("user-agent", "lenso-auth-github")
            .send()
            .await
            .map_err(github_error)?
            .text()
            .await
            .map_err(github_error)?;

        serde_json::from_str(&body).map_err(|source| {
            AppError::new(ErrorCode::Unauthorized, "GitHub user lookup failed").with_source(source)
        })
    }

    async fn load_primary_email(
        &self,
        config: &ResolvedGitHubAuthConfig,
        access_token: &str,
    ) -> AppResult<Option<String>> {
        let body = self
            .http
            .get(format!(
                "{}/user/emails",
                config.api_url.trim_end_matches('/')
            ))
            .header("accept", "application/vnd.github+json")
            .header("x-github-api-version", GITHUB_REST_API_VERSION)
            .header("authorization", format!("Bearer {access_token}"))
            .header("user-agent", "lenso-auth-github")
            .send()
            .await
            .map_err(github_error)?
            .text()
            .await
            .map_err(github_error)?;
        let emails: Vec<GitHubEmail> = serde_json::from_str(&body).map_err(|source| {
            AppError::new(ErrorCode::Unauthorized, "GitHub email lookup failed").with_source(source)
        })?;

        Ok(emails
            .iter()
            .find(|email| email.primary && email.verified)
            .or_else(|| emails.iter().find(|email| email.verified))
            .map(|email| email.email.clone()))
    }
}

#[derive(Debug, Deserialize)]
struct GitHubTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    #[serde(default)]
    primary: bool,
    #[serde(default)]
    verified: bool,
}

fn github_error(source: reqwest::Error) -> AppError {
    AppError::new(ErrorCode::Unauthorized, "GitHub OAuth request failed").with_source(source)
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
