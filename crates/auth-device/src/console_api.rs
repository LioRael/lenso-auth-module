use crate::repositories::PostgresAuthDeviceRepository;
use auth::console_api::validate_surface_request;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use platform_core::{AppContext, AppError, ErrorCode};
use platform_http::responses::json;
use platform_http::{
    ApiErrorResponse, ApiOpenApiRouter, ErrorResponse, HttpRequestContext, OpenApiRouter, routes,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

pub const AUTH_DEVICE_CONTRACT_DIGEST: &str =
    "sha256:89fc2a46836cb0bb3d7831276d20d37923ff63be3e04087b6d38866fbd14b052";
pub const LIST_DEVICES_OPERATION: &str = "auth-device/http/GET:/devices";

#[derive(Debug, Deserialize)]
pub struct AuthDeviceConsoleListQuery {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthDeviceConsoleRecord {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub trusted_at: Option<DateTime<Utc>>,
    pub primary_at: Option<DateTime<Utc>>,
    pub last_seen_ip: Option<String>,
    pub last_seen_user_agent: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthDeviceConsolePage {
    pub records: Vec<AuthDeviceConsoleRecord>,
    pub next_cursor: Option<String>,
}

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new().routes(routes!(list_devices))
}

#[utoipa::path(
    get,
    path = "/v1/auth/device/console/devices",
    operation_id = "auth_device_console_list_devices",
    tag = "auth-device-console",
    params(("limit" = Option<i64>, Query), ("cursor" = Option<String>, Query)),
    responses(
        (status = 200, body = AuthDeviceConsolePage, content_type = "application/json"),
        (status = 400, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 403, body = ErrorResponse, content_type = "application/problem+json"),
        (status = 500, body = ErrorResponse, content_type = "application/problem+json")
    )
)]
async fn list_devices(
    State(ctx): State<AppContext>,
    HttpRequestContext(request_ctx): HttpRequestContext,
    headers: HeaderMap,
    Query(query): Query<AuthDeviceConsoleListQuery>,
) -> Result<Json<AuthDeviceConsolePage>, ApiErrorResponse> {
    validate_surface_request(
        &headers,
        AUTH_DEVICE_CONTRACT_DIGEST,
        LIST_DEVICES_OPERATION,
        crate::module::AUTH_DEVICE_READ,
        &ctx,
        &request_ctx,
    )?;
    let limit = query.limit.unwrap_or(100);
    if !(1..=200).contains(&limit) {
        return Err(ApiErrorResponse::with_context(
            AppError::new(ErrorCode::Validation, "limit must be between 1 and 200"),
            &request_ctx,
        ));
    }
    if query.cursor.as_deref().is_some_and(str::is_empty) {
        return Err(ApiErrorResponse::with_context(
            AppError::new(ErrorCode::Validation, "cursor must be non-empty"),
            &request_ctx,
        ));
    }
    let rows = PostgresAuthDeviceRepository::new(ctx.db.clone())
        .list(limit + 1, query.cursor.as_deref())
        .await
        .map_err(|error| ApiErrorResponse::with_context(error, &request_ctx))?;
    let has_more = i64::try_from(rows.len()).is_ok_and(|count| count > limit);
    let records = rows
        .into_iter()
        .take(usize::try_from(limit).unwrap_or_default())
        .map(|device| AuthDeviceConsoleRecord {
            id: device.id,
            user_id: device.user_id.0,
            created_at: device.created_at,
            updated_at: device.updated_at,
            trusted_at: device.trusted_at,
            primary_at: device.primary_at,
            last_seen_ip: device.last_seen_ip,
            last_seen_user_agent: device.last_seen_user_agent,
        })
        .collect::<Vec<_>>();
    let next_cursor = has_more
        .then(|| records.last().map(|device| device.id.clone()))
        .flatten();
    Ok(json(AuthDeviceConsolePage {
        records,
        next_cursor,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn committed_contract_digest_matches_the_surface_client() {
        let contract = include_bytes!(
            "../../../packages/auth-device-console/src/auth-device-business-api.v1.json"
        );
        let digest = Sha256::digest(contract)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(format!("sha256:{digest}"), AUTH_DEVICE_CONTRACT_DIGEST);
    }
}
