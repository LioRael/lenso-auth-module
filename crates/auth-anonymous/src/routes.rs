use crate::dto::{AnonymousSessionResponse, AnonymousSignInRequest};
use crate::repositories::{AnonymousAuthRepository, AnonymousSessionOptions};
use auth::resolver::SESSION_COOKIE_NAME;
use auth::session_policy::AuthSessionPolicyHandle;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use platform_core::{AppContext, is_local_development_environment};
use platform_http::responses::json;
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, JsonBody, OpenApiRouter,
    routes,
};

const SESSION_TTL_HOURS: i64 = 12;

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new().routes(routes!(sign_in))
}

#[utoipa::path(
    post,
    path = "/v1/auth/anonymous/login",
    operation_id = "auth_anonymous_login",
    tag = "auth",
    request_body(
        content = AnonymousSignInRequest,
        content_type = "application/json",
        description = "Create an anonymous auth session"
    ),
    params(
        ("x-request-id" = Option<String>, Header, description = "Optional caller-provided request identifier"),
        ("x-correlation-id" = Option<String>, Header, description = "Optional caller-provided correlation identifier")
    ),
    responses(
        (
            status = 200,
            description = "Anonymous session created",
            body = AnonymousSessionResponse,
            content_type = "application/json",
            headers(
                ("x-request-id" = String, description = "Request identifier for this HTTP request"),
                ("x-correlation-id" = String, description = "Correlation identifier shared across related work")
            )
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
async fn sign_in(
    State(ctx): State<AppContext>,
    session_policy: Option<Extension<AuthSessionPolicyHandle>>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    JsonBody(input): JsonBody<AnonymousSignInRequest>,
) -> Result<(HeaderMap, Json<AnonymousSessionResponse>), ApiErrorResponse> {
    let now = ctx.clock.now();
    let session = AnonymousAuthRepository::new_with_session_policy(
        ctx.db.clone(),
        session_policy_from_extension(session_policy).into_policy(),
    )
    .sign_in(
        ctx.ids.new_id("usr"),
        ctx.ids.new_id("auth_identity"),
        ctx.ids.new_id("sess"),
        now,
        now + Duration::hours(SESSION_TTL_HOURS),
        AnonymousSessionOptions {
            device_id: input.device_id,
            client: request_ctx.client.clone(),
        },
    )
    .await
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(session_to_response(
        session,
        now,
        secure_session_cookie(&ctx),
    ))
}

fn session_policy_from_extension(
    session_policy: Option<Extension<AuthSessionPolicyHandle>>,
) -> AuthSessionPolicyHandle {
    session_policy
        .map(|Extension(session_policy)| session_policy)
        .unwrap_or_default()
}

fn session_to_response(
    session: auth::models::AuthSession,
    now: DateTime<Utc>,
    secure_cookie: bool,
) -> (HeaderMap, Json<AnonymousSessionResponse>) {
    let mut headers = HeaderMap::new();
    let max_age_seconds = session
        .expires_at
        .signed_duration_since(now)
        .num_seconds()
        .max(0);
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&session_cookie_header(
            &session.token,
            max_age_seconds,
            secure_cookie,
        ))
        .expect("session cookie header should be valid"),
    );

    (
        headers,
        json(AnonymousSessionResponse {
            user_id: session.user_id.0,
            session_id: session.id,
            token: session.token,
            expires_at: session.expires_at,
            is_anonymous: true,
        }),
    )
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
