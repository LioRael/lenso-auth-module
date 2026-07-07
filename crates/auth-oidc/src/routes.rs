use crate::config::ResolvedOidcConfig;
use crate::dto::{OidcAuthorizeQuery, OidcTokenRequest, OidcTokenResponse};
use crate::repositories::{AuthorizationCodeInput, AuthorizationCodeRecord, OidcRepository};
use auth::models::AuthUserId;
use axum::extract::{Query, State};
use axum::response::Redirect;
use axum::{Form, Json};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use platform_core::error::ErrorDetail;
use platform_core::{ActorContext, AppContext, AppError, ErrorCode};
use platform_http::responses::json;
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, OpenApiRouter, routes,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const AUTH_CODE_TTL_MINUTES: i64 = 5;
const ID_TOKEN_TTL_SECONDS: i64 = 3600;
const ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
const MAX_PARAM_BYTES: usize = 2048;
const MIN_PKCE_CODE_CHALLENGE_BYTES: usize = 43;
const MAX_PKCE_CODE_CHALLENGE_BYTES: usize = 128;
const SUPPORTED_SCOPES: &[&str] = &["openid"];

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(openid_configuration))
        .routes(routes!(jwks))
        .routes(routes!(authorize))
        .routes(routes!(token))
}

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    operation_id = "auth_oidc_provider_metadata",
    tag = "auth",
    responses(
        (
            status = 200,
            description = "OIDC provider metadata",
            body = crate::dto::OidcProviderMetadataResponse,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "OIDC provider is not enabled",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Invalid OIDC provider configuration",
            body = ErrorResponse,
            content_type = "application/json"
        )
    )
)]
async fn openid_configuration(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
) -> Result<Json<crate::dto::OidcProviderMetadataResponse>, ApiErrorResponse> {
    let oidc = oidc_config(&ctx, &request_ctx)?;
    let issuer = oidc.issuer;
    Ok(json(crate::dto::OidcProviderMetadataResponse {
        authorization_endpoint: format!("{issuer}/oauth/authorize"),
        claims_supported: vec!["sub".to_owned()],
        code_challenge_methods_supported: vec!["S256".to_owned()],
        id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
        issuer: issuer.clone(),
        jwks_uri: format!("{issuer}/.well-known/jwks.json"),
        lenso_console_client_id: oidc.console_client_id,
        response_types_supported: vec!["code".to_owned()],
        scopes_supported: SUPPORTED_SCOPES
            .iter()
            .map(|scope| (*scope).to_owned())
            .collect(),
        subject_types_supported: vec!["public".to_owned()],
        token_endpoint: format!("{issuer}/oauth/token"),
        token_endpoint_auth_methods_supported: vec!["none".to_owned()],
    }))
}

#[utoipa::path(
    get,
    path = "/.well-known/jwks.json",
    operation_id = "auth_oidc_jwks",
    tag = "auth",
    responses(
        (
            status = 200,
            description = "OIDC JSON Web Key Set",
            body = crate::dto::OidcJwksResponse,
            content_type = "application/json"
        ),
        (
            status = 404,
            description = "OIDC provider is not enabled",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 500,
            description = "Invalid OIDC provider configuration",
            body = ErrorResponse,
            content_type = "application/json"
        )
    )
)]
async fn jwks(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
) -> Result<Json<crate::dto::OidcJwksResponse>, ApiErrorResponse> {
    let oidc = oidc_config(&ctx, &request_ctx)?;
    let keys = oidc
        .jwks
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(json(crate::dto::OidcJwksResponse { keys }))
}

#[utoipa::path(
    get,
    path = "/oauth/authorize",
    operation_id = "auth_oidc_authorize",
    tag = "auth",
    params(
        ("response_type" = String, Query, description = "Must be `code`"),
        ("client_id" = String, Query, description = "Registered OIDC client id"),
        ("redirect_uri" = String, Query, description = "Registered redirect URI"),
        ("scope" = String, Query, description = "Space-separated scopes including `openid`"),
        ("state" = Option<String>, Query, description = "Opaque client state echoed to the redirect URI"),
        ("nonce" = Option<String>, Query, description = "Opaque nonce stored with the authorization code"),
        ("code_challenge" = String, Query, description = "PKCE S256 code challenge"),
        ("code_challenge_method" = String, Query, description = "Must be `S256`")
    ),
    responses(
        (
            status = 303,
            description = "Redirects to the registered redirect URI with an authorization code"
        ),
        (
            status = 400,
            description = "Request validation failed",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Authentication is required",
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
async fn authorize(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    Query(query): Query<OidcAuthorizeQuery>,
) -> Result<Redirect, ApiErrorResponse> {
    let oidc = oidc_config(&ctx, &request_ctx)?;
    let ActorContext::User { user_id, .. } = &request_ctx.actor else {
        return Err(ApiErrorResponse::with_context(
            AppError::new(ErrorCode::Unauthorized, "Authentication is required"),
            &request_ctx,
        ));
    };
    let request = validate_authorize_query(&query, &oidc)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let code = OidcRepository::new(ctx.db.clone())
        .create_authorization_code(AuthorizationCodeInput {
            user_id: AuthUserId(user_id.clone()),
            client_id: request.client_id,
            redirect_uri: request.redirect_uri.clone(),
            scope: request.scope,
            code_challenge: request.code_challenge,
            code_challenge_method: "S256".to_owned(),
            nonce: request.nonce,
            created_at: now,
            expires_at: now + Duration::minutes(AUTH_CODE_TTL_MINUTES),
        })
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(Redirect::to(&redirect_with_authorization_code(
        &request.redirect_uri,
        &code.code,
        request.state.as_deref(),
    )))
}

#[utoipa::path(
    post,
    path = "/oauth/token",
    operation_id = "auth_oidc_token",
    tag = "auth",
    request_body(
        content = crate::dto::OidcTokenRequest,
        content_type = "application/x-www-form-urlencoded"
    ),
    responses(
        (
            status = 200,
            description = "OIDC token response",
            body = crate::dto::OidcTokenResponse,
            content_type = "application/json"
        ),
        (
            status = 400,
            description = "Request validation failed",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 401,
            description = "Invalid authorization grant",
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
async fn token(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    Form(form): Form<OidcTokenRequest>,
) -> Result<Json<OidcTokenResponse>, ApiErrorResponse> {
    let oidc = oidc_config(&ctx, &request_ctx)?;
    let request = validate_token_request(&form, &oidc)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let repository = OidcRepository::new(ctx.db.clone());
    let Some(record) = repository
        .find_authorization_code(&request.code, now)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?
    else {
        return Err(ApiErrorResponse::with_context(
            invalid_grant(),
            &request_ctx,
        ));
    };

    if record.client_id != request.client_id
        || record.redirect_uri != request.redirect_uri
        || record.code_challenge_method != "S256"
        || pkce_s256_challenge(&request.code_verifier) != record.code_challenge
    {
        return Err(ApiErrorResponse::with_context(
            invalid_grant(),
            &request_ctx,
        ));
    }

    let consumed = repository
        .consume_authorization_code(&request.code, now)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    if !consumed {
        return Err(ApiErrorResponse::with_context(
            invalid_grant(),
            &request_ctx,
        ));
    }

    let id_token = sign_id_token(&oidc, &record, now)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let session = auth::public::create_session(
        &ctx.db,
        &record.user_id,
        ctx.ids.new_id("sess"),
        new_access_token(),
        now,
        now + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS as i64),
    )
    .await
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(json(OidcTokenResponse {
        access_token: session.token,
        token_type: "Bearer".to_owned(),
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
        id_token,
        scope: record.scope,
    }))
}

fn oidc_config(
    ctx: &AppContext,
    request_ctx: &platform_core::RequestContext,
) -> Result<ResolvedOidcConfig, ApiErrorResponse> {
    crate::config::OidcConfig::from_context(ctx)
        .and_then(|config| {
            config
                .resolve()?
                .ok_or_else(|| AppError::new(ErrorCode::NotFound, "OIDC provider is not enabled"))
        })
        .map_err(|error| ApiErrorResponse::with_context(error, request_ctx))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedAuthorizeRequest {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedTokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

fn validate_authorize_query(
    query: &OidcAuthorizeQuery,
    oidc: &ResolvedOidcConfig,
) -> platform_core::AppResult<ValidatedAuthorizeRequest> {
    if required_param(query.response_type.as_deref(), "response_type")? != "code" {
        return Err(validation("response_type", "response_type must be code"));
    }

    let client_id = required_param(query.client_id.as_deref(), "client_id")?;
    if client_id != oidc.console_client_id {
        return Err(validation("client_id", "client_id is not registered"));
    }

    let redirect_uri = required_param(query.redirect_uri.as_deref(), "redirect_uri")?;
    if !oidc
        .console_redirect_uris
        .iter()
        .any(|allowed| allowed == redirect_uri)
    {
        return Err(validation("redirect_uri", "redirect_uri is not registered"));
    }

    let scope = required_param(query.scope.as_deref(), "scope")?;
    let requested_scopes = scope.split_whitespace().collect::<Vec<_>>();
    if !requested_scopes.contains(&"openid") {
        return Err(validation("scope", "scope must include openid"));
    }
    if requested_scopes
        .iter()
        .any(|scope| !SUPPORTED_SCOPES.contains(scope))
    {
        return Err(validation("scope", "scope contains an unsupported scope"));
    }

    let code_challenge = required_param(query.code_challenge.as_deref(), "code_challenge")?;
    validate_pkce_challenge(code_challenge)?;
    if required_param(
        query.code_challenge_method.as_deref(),
        "code_challenge_method",
    )? != "S256"
    {
        return Err(validation(
            "code_challenge_method",
            "code_challenge_method must be S256",
        ));
    }

    Ok(ValidatedAuthorizeRequest {
        client_id: client_id.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        scope: scope.to_owned(),
        state: optional_param(query.state.as_deref(), "state")?,
        nonce: optional_param(query.nonce.as_deref(), "nonce")?,
        code_challenge: code_challenge.to_owned(),
    })
}

fn validate_token_request(
    request: &OidcTokenRequest,
    oidc: &ResolvedOidcConfig,
) -> platform_core::AppResult<ValidatedTokenRequest> {
    let grant_type = required_param(request.grant_type.as_deref(), "grant_type")?;
    if grant_type != "authorization_code" {
        return Err(validation(
            "grant_type",
            "grant_type must be authorization_code",
        ));
    }

    let code = required_param(request.code.as_deref(), "code")?;

    let client_id = required_param(request.client_id.as_deref(), "client_id")?;
    if client_id != oidc.console_client_id {
        return Err(validation("client_id", "client_id is not registered"));
    }

    let redirect_uri = required_param(request.redirect_uri.as_deref(), "redirect_uri")?;
    if !oidc
        .console_redirect_uris
        .iter()
        .any(|allowed| allowed == redirect_uri)
    {
        return Err(validation("redirect_uri", "redirect_uri is not registered"));
    }

    let code_verifier = required_param(request.code_verifier.as_deref(), "code_verifier")?;
    validate_pkce_verifier(code_verifier)?;

    Ok(ValidatedTokenRequest {
        grant_type: grant_type.to_owned(),
        code: code.to_owned(),
        redirect_uri: redirect_uri.to_owned(),
        client_id: client_id.to_owned(),
        code_verifier: code_verifier.to_owned(),
    })
}

fn required_param<'a>(value: Option<&'a str>, field: &str) -> platform_core::AppResult<&'a str> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| validation(field, &format!("{field} is required")))?;
    if value.len() > MAX_PARAM_BYTES {
        return Err(validation(field, &format!("{field} is too long")));
    }
    Ok(value)
}

fn optional_param(value: Option<&str>, field: &str) -> platform_core::AppResult<Option<String>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if value.len() > MAX_PARAM_BYTES {
        return Err(validation(field, &format!("{field} is too long")));
    }
    Ok(Some(value.to_owned()))
}

fn validate_pkce_challenge(value: &str) -> platform_core::AppResult<()> {
    let valid_len =
        (MIN_PKCE_CODE_CHALLENGE_BYTES..=MAX_PKCE_CODE_CHALLENGE_BYTES).contains(&value.len());
    let valid_chars = value.bytes().all(
        |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
    );
    if valid_len && valid_chars {
        return Ok(());
    }

    Err(validation(
        "code_challenge",
        "code_challenge must be a valid PKCE S256 challenge",
    ))
}

fn validate_pkce_verifier(value: &str) -> platform_core::AppResult<()> {
    let valid_len =
        (MIN_PKCE_CODE_CHALLENGE_BYTES..=MAX_PKCE_CODE_CHALLENGE_BYTES).contains(&value.len());
    let valid_chars = value.bytes().all(
        |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'),
    );
    if valid_len && valid_chars {
        return Ok(());
    }

    Err(validation(
        "code_verifier",
        "code_verifier must be a valid PKCE verifier",
    ))
}

fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_no_pad(digest.as_ref())
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut encoded = String::with_capacity(((bytes.len() + 2) / 3) * 4);
    let mut chunks = bytes.chunks_exact(3);
    for chunk in &mut chunks {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];
        encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
        encoded.push(char::from(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]));
        encoded.push(char::from(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]));
        encoded.push(char::from(TABLE[(b2 & 0x3f) as usize]));
    }

    match chunks.remainder() {
        [b0] => {
            encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
            encoded.push(char::from(TABLE[((b0 & 0x03) << 4) as usize]));
        }
        [b0, b1] => {
            encoded.push(char::from(TABLE[(b0 >> 2) as usize]));
            encoded.push(char::from(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]));
            encoded.push(char::from(TABLE[((b1 & 0x0f) << 2) as usize]));
        }
        [] => {}
        _ => unreachable!("remainder length is at most two"),
    }

    encoded
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
}

fn sign_id_token(
    oidc: &ResolvedOidcConfig,
    record: &AuthorizationCodeRecord,
    now: DateTime<Utc>,
) -> platform_core::AppResult<String> {
    let iat = now.timestamp() as u64;
    let exp = (now + Duration::seconds(ID_TOKEN_TTL_SECONDS)).timestamp() as u64;
    let claims = IdTokenClaims {
        iss: oidc.issuer.clone(),
        sub: record.user_id.0.clone(),
        aud: record.client_id.clone(),
        iat,
        exp,
        nonce: record.nonce.clone(),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = oidc.id_token_key_id.clone();
    let key =
        EncodingKey::from_rsa_pem(oidc.id_token_private_key_pem.as_bytes()).map_err(|source| {
            AppError::new(ErrorCode::Internal, "Invalid OIDC signing key").with_source(source)
        })?;

    encode(&header, &claims, &key).map_err(|source| {
        AppError::new(ErrorCode::Internal, "Failed to issue ID token").with_source(source)
    })
}

fn new_access_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness should be available");

    let mut token = String::with_capacity("oidc_access_".len() + bytes.len() * 2);
    token.push_str("oidc_access_");
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

fn redirect_with_authorization_code(redirect_uri: &str, code: &str, state: Option<&str>) -> String {
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut uri = format!(
        "{redirect_uri}{separator}code={}",
        percent_encode_query_value(code)
    );
    if let Some(state) = state.map(str::trim).filter(|value| !value.is_empty()) {
        uri.push_str("&state=");
        uri.push_str(&percent_encode_query_value(state));
    }
    uri
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

fn invalid_grant() -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Invalid authorization grant")
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
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use platform_core::config::ConsoleConfig;
    use platform_core::{
        AppConfig, AuthConfig, DatabaseConfig, HttpConfig, LoggingEventPublisher, ModuleConfig,
        ModuleSourcesConfig, RedisConfig, ServiceConfig, TelemetryConfig,
    };
    use platform_http::request_context_middleware;
    use serde_json::{Value, json};
    use sqlx::postgres::PgPoolOptions;
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn discovery_returns_404_when_disabled() {
        let response = test_app(false)
            .oneshot(get("/.well-known/openid-configuration"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn discovery_and_jwks_use_static_module_config() {
        let app = test_app(true);

        let metadata = app
            .clone()
            .oneshot(get("/.well-known/openid-configuration"))
            .await
            .expect("metadata request should complete");
        assert_eq!(metadata.status(), StatusCode::OK);
        let metadata = response_json(metadata).await;
        assert_eq!(metadata["issuer"], "https://example.com");
        assert_eq!(
            metadata["authorization_endpoint"],
            "https://example.com/oauth/authorize"
        );
        assert_eq!(metadata["lenso_console_client_id"], "lenso-console");

        let jwks = app
            .oneshot(get("/.well-known/jwks.json"))
            .await
            .expect("jwks request should complete");
        assert_eq!(jwks.status(), StatusCode::OK);
        let jwks = response_json(jwks).await;
        assert_eq!(jwks["keys"][0]["kid"], "test-key");
    }

    #[tokio::test]
    async fn authorize_rejects_unregistered_redirect_uri() {
        let challenge = "a".repeat(MIN_PKCE_CODE_CHALLENGE_BYTES);
        let response = test_app(true)
            .oneshot(get_as_user(&format!(
                "/oauth/authorize?response_type=code&client_id=lenso-console&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback&scope=openid&code_challenge={challenge}&code_challenge_method=S256"
            )))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_json(response).await;
        assert_eq!(body["status"], StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(body["errors"][0]["field"], "redirect_uri");
    }

    #[test]
    fn authorize_redirect_encodes_state() {
        assert_eq!(
            redirect_with_authorization_code(
                "https://console.example.com/callback",
                "oidc_code_abc",
                Some("hello world&x=1"),
            ),
            "https://console.example.com/callback?code=oidc_code_abc&state=hello%20world%26x%3D1",
        );
    }

    #[test]
    fn pkce_s256_challenge_matches_rfc7636_vector() {
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
    }

    fn test_app(enabled: bool) -> axum::Router {
        let (router, _) = router().split_for_parts();
        let ctx = test_context(enabled);
        router
            .layer(middleware::from_fn_with_state(
                ctx.clone(),
                request_context_middleware,
            ))
            .with_state(ctx)
    }

    fn test_context(enabled: bool) -> AppContext {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://lenso:lenso@127.0.0.1:5432/lenso")
            .expect("lazy pool should build");
        AppContext::new(test_config(enabled), db, Arc::new(LoggingEventPublisher))
    }

    fn test_config(enabled: bool) -> AppConfig {
        let mut values = BTreeMap::new();
        values.insert("enabled".to_owned(), json!(enabled));
        values.insert("issuer".to_owned(), json!("https://example.com/"));
        values.insert(
            "console_redirect_uris".to_owned(),
            json!(["https://console.example.com/callback"]),
        );
        values.insert(
            "jwks".to_owned(),
            json!({
                "keys": [{
                    "alg": "RS256",
                    "e": "AQAB",
                    "kid": "test-key",
                    "kty": "RSA",
                    "n": "test-modulus",
                    "use": "sig"
                }]
            }),
        );
        values.insert(
            "id_token_private_key_pem".to_owned(),
            json!("test-private-key"),
        );
        values.insert("id_token_key_id".to_owned(), json!("test-key"));
        let mut modules = BTreeMap::new();
        modules.insert(
            crate::config::CONFIG_PREFIX.to_owned(),
            ModuleConfig {
                enabled: None,
                values,
            },
        );

        AppConfig {
            auth: AuthConfig::default(),
            console: ConsoleConfig::default(),
            database: DatabaseConfig {
                max_connections: 1,
                url: "postgres://lenso:lenso@127.0.0.1:5432/lenso".to_owned(),
            },
            http: HttpConfig::default(),
            module_sources: ModuleSourcesConfig::default(),
            modules,
            redis: RedisConfig::default(),
            service: ServiceConfig {
                environment: "local".to_owned(),
                name: "auth-oidc-test".to_owned(),
            },
            telemetry: TelemetryConfig::default(),
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build")
    }

    fn get_as_user(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header("authorization", "Bearer dev-user:usr_route")
            .body(Body::empty())
            .expect("request should build")
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        serde_json::from_slice(&body).expect("body should be json")
    }
}
