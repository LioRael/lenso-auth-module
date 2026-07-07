use crate::dto::{
    PhoneOtpStartResponse, PhonePasswordUpdatedResponse, PhoneSessionPrimaryIdentifier,
    PhoneSessionResponse,
};
use crate::phone::normalize_phone_e164;
use crate::repositories::{
    LoginPhonePasswordOptions, PhoneAuthRepository, PhoneOtpPurpose, SetPhonePasswordOptions,
    StartOtpInput, VerifyOtpOptions,
};
use auth::models::{AuthSession, AuthUserId};
use auth::resolver::SESSION_COOKIE_NAME;
use auth::session_policy::AuthSessionPolicyHandle;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, HeaderValue};
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use platform_core::error::ErrorDetail;
use platform_core::{
    ActorContext, AppContext, AppError, AppResult, ErrorCode, is_local_development_environment,
};
use platform_http::responses::json;
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, JsonBody, OpenApiRouter,
    routes,
};

const SESSION_TTL_HOURS: i64 = 12;

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(start_otp))
        .routes(routes!(verify_otp))
        .routes(routes!(set_password))
        .routes(routes!(login_password))
}

#[utoipa::path(
    post,
    path = "/v1/auth/phone/otp/start",
    operation_id = "auth_phone_otp_start",
    tag = "auth",
    request_body(
        content = crate::dto::PhoneOtpStartRequest,
        content_type = "application/json",
        description = "Start a phone SMS OTP challenge"
    ),
    params(
        ("x-request-id" = Option<String>, Header, description = "Optional caller-provided request identifier"),
        ("x-correlation-id" = Option<String>, Header, description = "Optional caller-provided correlation identifier")
    ),
    responses(
        (
            status = 200,
            description = "Phone OTP challenge started",
            body = PhoneOtpStartResponse,
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
async fn start_otp(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    JsonBody(input): JsonBody<crate::dto::PhoneOtpStartRequest>,
) -> Result<Json<PhoneOtpStartResponse>, ApiErrorResponse> {
    let config = crate::config::AuthPhoneConfig::from_context(&ctx)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let purpose = parse_otp_purpose(&input.purpose)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let challenge = PhoneAuthRepository::new(ctx.db.clone())
        .start_otp(StartOtpInput {
            phone: &input.phone,
            purpose,
            challenge_id: ctx.ids.new_id("phone_otp_challenge"),
            now,
            config: &config,
            client: request_ctx.client.clone(),
        })
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(json(PhoneOtpStartResponse {
        challenge_id: challenge.id,
        expires_at: challenge.expires_at,
        resend_after: challenge.resend_after,
        debug_code: challenge.debug_code,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/phone/otp/verify",
    operation_id = "auth_phone_otp_verify",
    tag = "auth",
    request_body(
        content = crate::dto::PhoneOtpVerifyRequest,
        content_type = "application/json",
        description = "Verify a phone SMS OTP challenge and create a session"
    ),
    params(
        ("x-request-id" = Option<String>, Header, description = "Optional caller-provided request identifier"),
        ("x-correlation-id" = Option<String>, Header, description = "Optional caller-provided correlation identifier")
    ),
    responses(
        (
            status = 200,
            description = "Phone OTP verification successful",
            body = PhoneSessionResponse,
            content_type = "application/json",
            headers(
                ("set-cookie" = String, description = "HTTP-only session cookie"),
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
            status = 401,
            description = "Invalid or expired phone OTP",
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
async fn verify_otp(
    State(ctx): State<AppContext>,
    session_policy: Option<Extension<AuthSessionPolicyHandle>>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    JsonBody(input): JsonBody<crate::dto::PhoneOtpVerifyRequest>,
) -> Result<(HeaderMap, Json<PhoneSessionResponse>), ApiErrorResponse> {
    let config = crate::config::AuthPhoneConfig::from_context(&ctx)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let now = ctx.clock.now();
    let phone_e164 = load_otp_challenge_phone_e164(&ctx, &input.challenge_id)
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let session = PhoneAuthRepository::new_with_session_policy(
        ctx.db.clone(),
        session_policy_from_extension(session_policy).into_policy(),
    )
    .verify_otp_with_options(VerifyOtpOptions {
        challenge_id: &input.challenge_id,
        code: &input.code,
        session_id: ctx.ids.new_id("sess"),
        user_id: ctx.ids.new_id("usr"),
        identity_id: ctx.ids.new_id("auth_identity"),
        now,
        expires_at: now + Duration::hours(SESSION_TTL_HOURS),
        config: &config,
        device_id: input.device_id,
        client: request_ctx.client.clone(),
        link_anonymous_user_id: actor_user_id(&request_ctx.actor),
    })
    .await
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?
    .ok_or_else(invalid_phone_otp)
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(session_to_response(
        session,
        &phone_e164,
        now,
        secure_session_cookie(&ctx),
    ))
}

#[utoipa::path(
    post,
    path = "/v1/auth/phone/password/set",
    operation_id = "auth_phone_password_set",
    tag = "auth",
    request_body(
        content = crate::dto::PhonePasswordSetRequest,
        content_type = "application/json",
        description = "Set or replace the password for the current phone identity"
    ),
    params(
        ("authorization" = Option<String>, Header, description = "Bearer session token or local development actor"),
        ("cookie" = Option<String>, Header, description = "Cookie header containing `lenso_session`"),
        ("x-request-id" = Option<String>, Header, description = "Optional caller-provided request identifier"),
        ("x-correlation-id" = Option<String>, Header, description = "Optional caller-provided correlation identifier")
    ),
    responses(
        (
            status = 200,
            description = "Phone password updated",
            body = PhonePasswordUpdatedResponse,
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
            status = 401,
            description = "Authentication is required",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 403,
            description = "Authenticated phone identity is required",
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
async fn set_password(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    JsonBody(input): JsonBody<crate::dto::PhonePasswordSetRequest>,
) -> Result<Json<PhonePasswordUpdatedResponse>, ApiErrorResponse> {
    let user_id = required_user_id(&request_ctx)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let config = auth_password::config::AuthPasswordConfig::from_context(&ctx)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let updated = PhoneAuthRepository::new(ctx.db.clone())
        .set_password(SetPhonePasswordOptions {
            user_id: &user_id,
            password: &input.password,
            now: ctx.clock.now(),
            config: &config,
        })
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    if !updated {
        return Err(ApiErrorResponse::with_context(
            phone_identity_required(),
            &request_ctx,
        ));
    }

    Ok(json(PhonePasswordUpdatedResponse { updated }))
}

#[utoipa::path(
    post,
    path = "/v1/auth/phone/password/login",
    operation_id = "auth_phone_password_login",
    tag = "auth",
    request_body(
        content = crate::dto::PhonePasswordLoginRequest,
        content_type = "application/json",
        description = "Create a session for a phone password identity"
    ),
    params(
        ("x-request-id" = Option<String>, Header, description = "Optional caller-provided request identifier"),
        ("x-correlation-id" = Option<String>, Header, description = "Optional caller-provided correlation identifier")
    ),
    responses(
        (
            status = 200,
            description = "Phone password authentication successful",
            body = PhoneSessionResponse,
            content_type = "application/json",
            headers(
                ("set-cookie" = String, description = "HTTP-only session cookie"),
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
            status = 401,
            description = "Invalid phone or password",
            body = ErrorResponse,
            content_type = "application/json"
        ),
        (
            status = 429,
            description = "Too many phone password login attempts",
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
async fn login_password(
    State(ctx): State<AppContext>,
    session_policy: Option<Extension<AuthSessionPolicyHandle>>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    JsonBody(input): JsonBody<crate::dto::PhonePasswordLoginRequest>,
) -> Result<(HeaderMap, Json<PhoneSessionResponse>), ApiErrorResponse> {
    let now = ctx.clock.now();
    let phone_e164 = normalize_phone_e164(&input.phone)
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let session = PhoneAuthRepository::new_with_session_policy(
        ctx.db.clone(),
        session_policy_from_extension(session_policy).into_policy(),
    )
    .login_password_with_options(LoginPhonePasswordOptions {
        phone: &input.phone,
        password: &input.password,
        session_id: ctx.ids.new_id("sess"),
        now,
        expires_at: now + Duration::hours(SESSION_TTL_HOURS),
        device_id: input.device_id,
        client: request_ctx.client.clone(),
    })
    .await
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?
    .ok_or_else(invalid_phone_password_credentials)
    .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;

    Ok(session_to_response(
        session,
        &phone_e164,
        now,
        secure_session_cookie(&ctx),
    ))
}

fn parse_otp_purpose(value: &str) -> AppResult<PhoneOtpPurpose> {
    match value.trim() {
        "sign_in" => Ok(PhoneOtpPurpose::SignIn),
        "password_setup" => Ok(PhoneOtpPurpose::PasswordSetup),
        "password_reset" => Ok(PhoneOtpPurpose::PasswordReset),
        _ => Err(AppError::validation(
            "Request validation failed",
            vec![ErrorDetail {
                field: Some("purpose".to_owned()),
                reason: "purpose must be one of: sign_in, password_setup, password_reset"
                    .to_owned(),
            }],
        )),
    }
}

fn required_user_id(request_ctx: &platform_core::RequestContext) -> AppResult<AuthUserId> {
    actor_user_id(&request_ctx.actor)
        .ok_or_else(|| AppError::new(ErrorCode::Unauthorized, "Authentication is required"))
}

fn actor_user_id(actor: &ActorContext) -> Option<AuthUserId> {
    match actor {
        ActorContext::User { user_id, .. } => Some(AuthUserId(user_id.clone())),
        ActorContext::Anonymous | ActorContext::Service { .. } | ActorContext::System => None,
    }
}

fn session_policy_from_extension(
    session_policy: Option<Extension<AuthSessionPolicyHandle>>,
) -> AuthSessionPolicyHandle {
    session_policy
        .map(|Extension(session_policy)| session_policy)
        .unwrap_or_default()
}

fn session_to_response(
    session: AuthSession,
    phone_e164: &str,
    now: DateTime<Utc>,
    secure_cookie: bool,
) -> (HeaderMap, Json<PhoneSessionResponse>) {
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
        json(PhoneSessionResponse {
            user_id: session.user_id.0,
            session_id: session.id,
            token: session.token,
            expires_at: session.expires_at,
            primary_identifier: phone_session_primary_identifier(phone_e164),
        }),
    )
}

async fn load_otp_challenge_phone_e164(ctx: &AppContext, challenge_id: &str) -> AppResult<String> {
    sqlx::query_scalar::<_, String>(
        r#"
        select phone_e164
        from auth_phone.otp_challenges
        where id = $1
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&ctx.db)
    .await
    .map_err(|source| {
        AppError::new(ErrorCode::Internal, "Phone OTP challenge lookup failed").with_source(source)
    })?
    .ok_or_else(invalid_phone_otp)
}

fn phone_session_primary_identifier(phone_e164: &str) -> PhoneSessionPrimaryIdentifier {
    let (country_code, national_number) = split_phone_e164(phone_e164);

    PhoneSessionPrimaryIdentifier {
        kind: "phone".to_owned(),
        country_code,
        masked_national_number: mask_national_phone_number(&national_number),
    }
}

fn split_phone_e164(phone_e164: &str) -> (String, String) {
    let phone = phone_e164.trim();
    if let Some(national_number) = phone.strip_prefix("+86") {
        return ("+86".to_owned(), national_number.to_owned());
    }

    let digits = phone.strip_prefix('+').unwrap_or(phone);
    let country_digits = digits.len().saturating_sub(10).clamp(1, 3);
    let (country_code, national_number) = digits.split_at(country_digits.min(digits.len()));

    (format!("+{country_code}"), national_number.to_owned())
}

fn mask_national_phone_number(phone: &str) -> String {
    if phone.len() <= 7 {
        return phone.to_owned();
    }

    format!("{}****{}", &phone[..3], &phone[phone.len() - 4..])
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

fn invalid_phone_otp() -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Invalid or expired phone OTP")
}

fn invalid_phone_password_credentials() -> AppError {
    AppError::new(ErrorCode::Unauthorized, "Invalid phone or password")
}

fn phone_identity_required() -> AppError {
    AppError::new(
        ErrorCode::Forbidden,
        "Authenticated phone identity is required",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_session_identifier_splits_country_code_and_masks_national_number() {
        let identifier = phone_session_primary_identifier("+8613800000201");

        assert_eq!(identifier.kind, "phone");
        assert_eq!(identifier.country_code, "+86");
        assert_eq!(identifier.masked_national_number, "138****0201");
    }
}
