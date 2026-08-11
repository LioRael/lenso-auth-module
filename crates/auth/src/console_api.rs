use crate::models::AuthUserId;
use crate::repositories::{AuthUserRepository, PostgresAuthUserRepository};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use platform_core::{AppContext, AppError, ErrorCode};
use platform_http::responses::json;
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, JsonBody, OpenApiRouter,
    routes,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const AUTH_CONTRACT_DIGEST: &str =
    "sha256:b57f7626fb6eac67b0595c17894671f08782ec4ca7d8c69990769048570999ed";
pub const LIST_USERS_OPERATION: &str = "auth/http/GET:/users";
pub const LIST_SESSIONS_OPERATION: &str = "auth/http/GET:/sessions";
pub const DISABLE_USER_OPERATION: &str = "auth/http/POST:/users/{id}/disable";
pub const ENABLE_USER_OPERATION: &str = "auth/http/POST:/users/{id}/enable";
pub const REVOKE_SESSION_OPERATION: &str = "auth/http/POST:/sessions/{id}/revoke";

const DEFAULT_PAGE_LIMIT: i64 = 100;
const MAX_PAGE_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
pub struct AuthConsoleListQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthConsoleUser {
    pub id: String,
    pub is_anonymous: bool,
    pub created_at: DateTime<Utc>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub disabled_reason: Option<String>,
    pub disabled_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthConsoleSession {
    pub id: String,
    pub user_id: String,
    pub device_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthConsoleUserPage {
    pub records: Vec<AuthConsoleUser>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthConsoleSessionPage {
    pub records: Vec<AuthConsoleSession>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableAuthUserRequest {
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub disabled_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthUserMutationResponse {
    pub user_id: String,
    pub changed: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthSessionMutationResponse {
    pub session_id: String,
    pub revoked: bool,
}

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(list_users))
        .routes(routes!(list_sessions))
        .routes(routes!(disable_user))
        .routes(routes!(enable_user))
        .routes(routes!(revoke_session))
}

#[utoipa::path(
    get,
    path = "/v1/auth/console/users",
    operation_id = "auth_console_list_users",
    tag = "auth-console",
    params(
        ("limit" = Option<i64>, Query, minimum = 1, maximum = 200),
        ("cursor" = Option<String>, Query)
    ),
    responses(
        (status = 200, body = AuthConsoleUserPage, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn list_users(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Query(query): Query<AuthConsoleListQuery>,
) -> Result<Json<AuthConsoleUserPage>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_CONTRACT_DIGEST,
        LIST_USERS_OPERATION,
        crate::module::AUTH_USERS_READ,
        &ctx,
        &request_ctx,
    )?;
    let (limit, cursor) = list_input(query, &request_ctx)?;
    let rows = PostgresAuthUserRepository::from_context(&ctx)
        .list(limit + 1, cursor.as_deref())
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
    let mut records = rows
        .into_iter()
        .take(usize::try_from(limit).unwrap_or_default())
        .map(|user| AuthConsoleUser {
            id: user.id.0,
            is_anonymous: user.is_anonymous,
            created_at: user.created_at,
            disabled_at: user.disabled_at,
            disabled_reason: user.disabled_reason,
            disabled_until: user.disabled_until,
        })
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| records.last().map(|user| user.id.clone()))
        .flatten();
    records.shrink_to_fit();
    Ok(json(AuthConsoleUserPage {
        records,
        next_cursor,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/auth/console/sessions",
    operation_id = "auth_console_list_sessions",
    tag = "auth-console",
    params(
        ("limit" = Option<i64>, Query, minimum = 1, maximum = 200),
        ("cursor" = Option<String>, Query)
    ),
    responses(
        (status = 200, body = AuthConsoleSessionPage, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn list_sessions(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Query(query): Query<AuthConsoleListQuery>,
) -> Result<Json<AuthConsoleSessionPage>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_CONTRACT_DIGEST,
        LIST_SESSIONS_OPERATION,
        crate::module::AUTH_SESSIONS_READ,
        &ctx,
        &request_ctx,
    )?;
    let (limit, cursor) = list_input(query, &request_ctx)?;
    let rows = PostgresAuthUserRepository::from_context(&ctx)
        .list_sessions(limit + 1, cursor.as_deref())
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
    let records = rows
        .into_iter()
        .take(usize::try_from(limit).unwrap_or_default())
        .map(|session| AuthConsoleSession {
            id: session.id,
            user_id: session.user_id.0,
            device_id: session.device_id,
            client_ip: session.client_ip,
            user_agent: session.user_agent,
            created_at: session.created_at,
            expires_at: session.expires_at,
            revoked_at: session.revoked_at,
        })
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| records.last().map(|session| session.id.clone()))
        .flatten();
    Ok(json(AuthConsoleSessionPage {
        records,
        next_cursor,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/console/users/{user_id}/disable",
    operation_id = "auth_console_disable_user",
    tag = "auth-console",
    params(("user_id" = String, Path)),
    request_body = DisableAuthUserRequest,
    responses(
        (status = 200, body = AuthUserMutationResponse, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 404, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn disable_user(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    JsonBody(input): JsonBody<DisableAuthUserRequest>,
) -> Result<Json<AuthUserMutationResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_CONTRACT_DIGEST,
        DISABLE_USER_OPERATION,
        crate::module::AUTH_USERS_MANAGE,
        &ctx,
        &request_ctx,
    )?;
    require_resource_id(&user_id, "user_id", &request_ctx)?;
    if input
        .disabled_until
        .is_some_and(|until| until <= ctx.clock.now())
    {
        return Err(validation_error(
            "disabled_until must be in the future",
            &request_ctx,
        ));
    }
    let reason = input
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let changed = PostgresAuthUserRepository::from_context(&ctx)
        .set_user_disabled_at(
            &AuthUserId(user_id.clone()),
            Some(ctx.clock.now()),
            reason,
            input.disabled_until,
        )
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    require_changed(changed, "Auth user was not found", &request_ctx)?;
    Ok(json(AuthUserMutationResponse { user_id, changed }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/console/users/{user_id}/enable",
    operation_id = "auth_console_enable_user",
    tag = "auth-console",
    params(("user_id" = String, Path)),
    responses(
        (status = 200, body = AuthUserMutationResponse, content_type = "application/json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 404, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn enable_user(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<AuthUserMutationResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_CONTRACT_DIGEST,
        ENABLE_USER_OPERATION,
        crate::module::AUTH_USERS_MANAGE,
        &ctx,
        &request_ctx,
    )?;
    require_resource_id(&user_id, "user_id", &request_ctx)?;
    let changed = PostgresAuthUserRepository::from_context(&ctx)
        .set_user_disabled_at(&AuthUserId(user_id.clone()), None, None, None)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    require_changed(changed, "Auth user was not found", &request_ctx)?;
    Ok(json(AuthUserMutationResponse { user_id, changed }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/console/sessions/{session_id}/revoke",
    operation_id = "auth_console_revoke_session",
    tag = "auth-console",
    params(("session_id" = String, Path)),
    responses(
        (status = 200, body = AuthSessionMutationResponse, content_type = "application/json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn revoke_session(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<AuthSessionMutationResponse>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_CONTRACT_DIGEST,
        REVOKE_SESSION_OPERATION,
        crate::module::AUTH_SESSIONS_REVOKE,
        &ctx,
        &request_ctx,
    )?;
    require_resource_id(&session_id, "session_id", &request_ctx)?;
    let revoked = PostgresAuthUserRepository::from_context(&ctx)
        .revoke_session_by_id(&session_id, ctx.clock.now())
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    Ok(json(AuthSessionMutationResponse {
        session_id,
        revoked,
    }))
}

fn list_input(
    query: AuthConsoleListQuery,
    request_ctx: &platform_core::RequestContext,
) -> Result<(i64, Option<String>), ApiErrorResponse> {
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(validation_error(
            "limit must be between 1 and 200",
            request_ctx,
        ));
    }
    if query.cursor.as_deref().is_some_and(str::is_empty) {
        return Err(validation_error("cursor must be non-empty", request_ctx));
    }
    Ok((limit, query.cursor))
}

pub fn validate_surface_request(
    headers: &HeaderMap,
    expected_contract_digest: &str,
    expected_operation: &str,
    expected_capability: &str,
    ctx: &AppContext,
    request_ctx: &platform_core::RequestContext,
) -> Result<(), ApiErrorResponse> {
    let authority = header(headers, "x-lenso-console-delegated-authority");
    let deadline =
        header(headers, "x-lenso-deadline-unix-ms").and_then(|value| value.parse::<i64>().ok());
    let valid = header(headers, "x-lenso-console-contract-digest")
        == Some(expected_contract_digest)
        && header(headers, "x-lenso-console-operation-id") == Some(expected_operation)
        && header(headers, "x-lenso-console-capability") == Some(expected_capability)
        && header(headers, "x-lenso-console-delegated-actor").is_some_and(non_empty)
        && header(headers, "x-lenso-console-service-id").is_some_and(non_empty)
        && authority.is_some_and(valid_digest)
        && deadline.is_some_and(|value| value > ctx.clock.now().timestamp_millis());
    if !valid {
        return Err(ApiErrorResponse::with_context(
            AppError::new(
                ErrorCode::Forbidden,
                "Auth Business API request is not bound to an accepted Console Surface operation",
            ),
            request_ctx,
        ));
    }
    Ok(())
}

fn require_resource_id(
    value: &str,
    field: &str,
    request_ctx: &platform_core::RequestContext,
) -> Result<(), ApiErrorResponse> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(validation_error(
            format!("{field} contains an unsafe path character"),
            request_ctx,
        ));
    }
    Ok(())
}

fn require_changed(
    changed: bool,
    message: &str,
    request_ctx: &platform_core::RequestContext,
) -> Result<(), ApiErrorResponse> {
    if !changed {
        return Err(ApiErrorResponse::with_context(
            AppError::new(ErrorCode::NotFound, message),
            request_ctx,
        ));
    }
    Ok(())
}

fn validation_error(
    message: impl Into<String>,
    request_ctx: &platform_core::RequestContext,
) -> ApiErrorResponse {
    ApiErrorResponse::with_context(
        AppError::new(ErrorCode::Validation, message.into()),
        request_ctx,
    )
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn committed_contract_digest_matches_the_surface_client() {
        let contract =
            include_bytes!("../../../packages/auth-console/src/auth-business-api.v1.json");
        let digest = Sha256::digest(contract)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let actual = format!("sha256:{digest}");
        assert_eq!(actual, AUTH_CONTRACT_DIGEST);
    }

    #[test]
    fn resource_ids_are_path_segment_safe() {
        assert!(
            "usr_1.test-2~ok"
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || b"._~-".contains(&byte) })
        );
        assert!(
            !"../usr_1"
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || b"._~-".contains(&byte) })
        );
    }
}
