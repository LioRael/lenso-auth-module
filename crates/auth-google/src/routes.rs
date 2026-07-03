use crate::config::ResolvedGoogleAuthConfig;
use crate::repository::{GOOGLE_PROVIDER, GoogleAuthRepository, GoogleIdentityInput};
use auth::resolver::SESSION_COOKIE_NAME;
use auth::session_policy::AllowSessionPolicy;
use auth_oauth::flow::{
    OAuthFlowInput, OAuthFlowRepository, normalize_return_to, pkce_s256_challenge,
};
use axum::Extension;
use axum::extract::{Query, State};
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::Redirect;
use chrono::Duration;
use platform_core::error::ErrorDetail;
use platform_core::{AppContext, AppError, ErrorCode, is_local_development_environment};
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, OpenApiRouter, routes,
};
use std::fmt::Write as _;

const OAUTH_FLOW_TTL_MINUTES: i64 = 10;
const SESSION_TTL_HOURS: i64 = 12;

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(start))
        .routes(routes!(callback))
}

#[utoipa::path(
    get,
    path = "/v1/auth/google/start",
    operation_id = "auth_google_start",
    tag = "auth",
    params(
        ("return_to" = Option<String>, Query, description = "Safe relative path to redirect to after login")
    ),
    responses(
        (
            status = 303,
            description = "Redirects to Google OAuth authorization"
        ),
        (
            status = 400,
            description = "Request validation failed",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            content_type = "application/json"
        )
    )
)]
async fn start(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    Query(query): Query<crate::dto::GoogleStartQuery>,
) -> Result<Redirect, ApiErrorResponse> {
    let config = crate::config::GoogleAuthConfig::from_context(&ctx)
        .and_then(|config| config.resolve())
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let return_to = normalize_return_to(query.return_to.as_deref())
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let flow = OAuthFlowRepository::new(ctx.db.clone())
        .create_flow(OAuthFlowInput {
            provider: GOOGLE_PROVIDER.to_owned(),
            return_to,
            client: request_ctx.client.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(OAUTH_FLOW_TTL_MINUTES),
        })
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let code_challenge = pkce_s256_challenge(&flow.code_verifier);

    Ok(Redirect::to(&build_authorize_url(
        &config,
        &flow.state,
        &code_challenge,
    )))
}

#[utoipa::path(
    get,
    path = "/v1/auth/google/callback",
    operation_id = "auth_google_callback",
    tag = "auth",
    params(
        ("code" = Option<String>, Query, description = "Temporary Google OAuth code"),
        ("state" = Option<String>, Query, description = "OAuth state returned by Google")
    ),
    responses(
        (
            status = 303,
            description = "Creates a Lenso session and redirects to the original return path"
        ),
        (
            status = 400,
            description = "Request validation failed",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Invalid Google authorization grant",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Internal server error",
            body = ErrorResponse,
            content_type = "application/json"
        )
    )
)]
async fn callback(
    State(ctx): State<AppContext>,
    google_client: Option<Extension<crate::client::GoogleOAuthClientHandle>>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    Query(query): Query<crate::dto::GoogleCallbackQuery>,
) -> Result<(HeaderMap, Redirect), ApiErrorResponse> {
    let config = crate::config::GoogleAuthConfig::from_context(&ctx)
        .and_then(|config| config.resolve())
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let code = required_query(query.code.as_deref(), "code")
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let state = required_query(query.state.as_deref(), "state")
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let flow = OAuthFlowRepository::new(ctx.db.clone())
        .consume_flow(GOOGLE_PROVIDER, state, now)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?
        .ok_or_else(invalid_grant)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    let google_client = google_client
        .map(|Extension(client)| client)
        .unwrap_or_else(|| std::sync::Arc::new(crate::client::ReqwestGoogleOAuthClient::default()));
    let access_token = google_client
        .exchange_code(&config, code, &flow.code_verifier)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let google_user = google_client
        .load_user(&config, &access_token.access_token)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let email = google_user
        .email
        .clone()
        .filter(|value| google_user.email_verified && !value.trim().is_empty());
    let display_name = google_user
        .name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| email.clone())
        .unwrap_or_else(|| google_user.sub.clone());
    let identity = GoogleAuthRepository::new(ctx.db.clone())
        .find_or_create_identity(GoogleIdentityInput {
            google_user_id: google_user.sub,
            display_name,
            email,
            picture_url: google_user.picture,
            user_id: ctx.ids.new_id("usr"),
            identity_id: ctx.ids.new_id("auth_identity"),
            now,
        })
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let session = auth::public::create_session_with_policy(
        &ctx.db,
        &identity.user_id,
        ctx.ids.new_id("sess"),
        new_session_token(),
        now,
        now + Duration::hours(SESSION_TTL_HOURS),
        auth::public::SessionCreateOptions {
            device_id: None,
            client: flow.client,
        },
        &AllowSessionPolicy,
    )
    .await
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie_header(
            &session.token,
            SESSION_TTL_HOURS * 60 * 60,
            secure_session_cookie(&ctx),
        ))
        .expect("session cookie header should be valid"),
    );
    Ok((headers, Redirect::to(&flow.return_to)))
}

fn build_authorize_url(
    config: &ResolvedGoogleAuthConfig,
    state: &str,
    code_challenge: &str,
) -> String {
    let mut url = format!(
        "{}?response_type=code&client_id={}",
        config.authorize_url,
        percent_encode_query_value(&config.client_id)
    );
    if let Some(redirect_uri) = &config.redirect_uri {
        url.push_str("&redirect_uri=");
        url.push_str(&percent_encode_query_value(redirect_uri));
    }
    url.push_str("&scope=");
    url.push_str(&percent_encode_query_value(&config.scope));
    url.push_str("&state=");
    url.push_str(&percent_encode_query_value(state));
    url.push_str("&code_challenge=");
    url.push_str(&percent_encode_query_value(code_challenge));
    url.push_str("&code_challenge_method=S256");
    url
}

fn percent_encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn required_query<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, AppError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| validation(field, &format!("{field} is required")))
}

fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness should be available");

    let mut token = String::with_capacity("google_session_".len() + bytes.len() * 2);
    token.push_str("google_session_");
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn session_cookie_header(token: &str, max_age_seconds: i64, secure: bool) -> String {
    let mut value = format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_seconds}"
    );
    if secure {
        value.push_str("; Secure");
    }
    value
}

fn secure_session_cookie(ctx: &AppContext) -> bool {
    !is_local_development_environment(&ctx.config.service.environment)
}

fn invalid_grant() -> AppError {
    AppError::new(
        ErrorCode::Unauthorized,
        "Invalid Google authorization grant",
    )
}

fn validation(field: &str, reason: &str) -> AppError {
    AppError::validation(
        "Request validation failed",
        vec![ErrorDetail {
            field: Some(field.to_owned()),
            reason: reason.to_owned(),
        }],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedGoogleAuthConfig;

    #[test]
    fn authorize_url_includes_state_pkce_and_scope() {
        let url = build_authorize_url(
            &ResolvedGoogleAuthConfig {
                client_id: "google-client".to_owned(),
                client_secret: "google-secret".to_owned(),
                redirect_uri: Some("https://app.example.com/v1/auth/google/callback".to_owned()),
                scope: "openid profile email".to_owned(),
                authorize_url: "https://accounts.google.example.test/o/oauth2/v2/auth".to_owned(),
                token_url: "https://oauth2.google.example.test/token".to_owned(),
                userinfo_url: "https://openidconnect.google.example.test/v1/userinfo".to_owned(),
            },
            "oauth_state_abc",
            "challenge/with+reserved=",
        );

        assert_eq!(
            url,
            "https://accounts.google.example.test/o/oauth2/v2/auth?response_type=code&client_id=google-client&redirect_uri=https%3A%2F%2Fapp.example.com%2Fv1%2Fauth%2Fgoogle%2Fcallback&scope=openid%20profile%20email&state=oauth_state_abc&code_challenge=challenge%2Fwith%2Breserved%3D&code_challenge_method=S256"
        );
    }
}
