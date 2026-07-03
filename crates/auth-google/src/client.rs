use crate::config::ResolvedGoogleAuthConfig;
use platform_core::{AppError, AppResult, ErrorCode};
use serde::Deserialize;
use std::sync::Arc;

pub type GoogleOAuthClientHandle = Arc<dyn GoogleOAuthClient>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoogleAccessToken {
    pub access_token: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GoogleUser {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub picture: Option<String>,
}

#[async_trait::async_trait]
pub trait GoogleOAuthClient: std::fmt::Debug + Send + Sync {
    async fn exchange_code(
        &self,
        config: &ResolvedGoogleAuthConfig,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<GoogleAccessToken>;

    async fn load_user(
        &self,
        config: &ResolvedGoogleAuthConfig,
        access_token: &str,
    ) -> AppResult<GoogleUser>;
}

#[derive(Debug, Clone)]
pub struct ReqwestGoogleOAuthClient {
    http: reqwest::Client,
}

impl Default for ReqwestGoogleOAuthClient {
    fn default() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl GoogleOAuthClient for ReqwestGoogleOAuthClient {
    async fn exchange_code(
        &self,
        config: &ResolvedGoogleAuthConfig,
        code: &str,
        code_verifier: &str,
    ) -> AppResult<GoogleAccessToken> {
        let mut body = format!(
            "client_id={}&client_secret={}&code={}&code_verifier={}&grant_type=authorization_code",
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
            .header("user-agent", "lenso-auth-google")
            .body(body)
            .send()
            .await
            .map_err(google_error)?
            .text()
            .await
            .map_err(google_error)?;

        let token: GoogleTokenResponse = serde_json::from_str(&response).map_err(|source| {
            AppError::new(
                ErrorCode::Unauthorized,
                "Google OAuth token exchange failed",
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
            .map(|access_token| GoogleAccessToken { access_token })
            .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "Google did not return a token"))
    }

    async fn load_user(
        &self,
        config: &ResolvedGoogleAuthConfig,
        access_token: &str,
    ) -> AppResult<GoogleUser> {
        let body = self
            .http
            .get(&config.userinfo_url)
            .header("accept", "application/json")
            .header("authorization", format!("Bearer {access_token}"))
            .header("user-agent", "lenso-auth-google")
            .send()
            .await
            .map_err(google_error)?
            .text()
            .await
            .map_err(google_error)?;

        serde_json::from_str(&body).map_err(|source| {
            AppError::new(ErrorCode::Unauthorized, "Google user lookup failed").with_source(source)
        })
    }
}

#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

fn google_error(source: reqwest::Error) -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Google OAuth request failed").with_source(source)
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
