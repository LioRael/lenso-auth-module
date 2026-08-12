use axum::Json;
use axum::http::{HeaderMap, HeaderValue, header};
use platform_http::{ApiOpenApiRouter, OpenApiRouter, routes};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const AUTH_CONSOLE_ARTIFACT_PATH: &str = "/v1/auth/console/artifact";
pub const AUTH_CONSOLE_RELEASE_PATH: &str = "/v1/auth/console/release";
pub const AUTH_CONSOLE_RELEASE_PROTOCOL: &str = "lenso.console-artifact-template.v1";

const AUTH_CONSOLE_ARTIFACT: &[u8] = include_bytes!("../artifacts/auth-console.tgz");
const AUTH_CONTRACT_DOCUMENT: &str = include_str!("../artifacts/auth-business-api.v1.json");

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
        .routes(routes!(get_console_artifact))
        .routes(routes!(get_console_release))
}

#[utoipa::path(
    get,
    path = "/v1/auth/console/artifact",
    operation_id = "auth_console_artifact",
    tag = "auth-console",
    responses((status = 200, description = "Exact Auth Console ESM artifact", content_type = "application/gzip"))
)]
async fn get_console_artifact() -> (HeaderMap, &'static [u8]) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    (headers, AUTH_CONSOLE_ARTIFACT)
}

#[utoipa::path(
    get,
    path = "/v1/auth/console/release",
    operation_id = "auth_console_release",
    tag = "auth-console",
    responses((status = 200, description = "Auth Module-owned Console artifact release template", body = serde_json::Value, content_type = "application/json"))
)]
async fn get_console_release() -> Json<Value> {
    Json(console_release_template())
}

#[must_use]
pub fn console_release_template() -> Value {
    let manifest = crate::module::manifest();
    let console_manifest = manifest.console_module_manifest("^2.1.0", "^2.0.0");
    json!({
        "protocol": AUTH_CONSOLE_RELEASE_PROTOCOL,
        "moduleId": manifest.module_id,
        "version": env!("CARGO_PKG_VERSION"),
        "manifest": manifest,
        "artifactPath": AUTH_CONSOLE_ARTIFACT_PATH,
        "artifact": {
            "digest": artifact_digest(),
            "format": "console_ui_esm",
            "protocolMajor": 1,
            "entry": "index.js",
            "entries": [
                { "name": "module", "path": "index.js" },
                { "name": "sessions", "path": "index.js?surface=sessions" },
                { "name": "users", "path": "index.js?surface=users" },
                { "name": "style", "path": "assets/stylex.css" }
            ],
            "styleAssets": [
                { "path": "assets/stylex.css", "order": 0 }
            ],
            "manifest": console_manifest,
            "requestedPermissions": []
        },
        "delivery": {
            "kind": "linked",
            "package": "lenso-module-auth",
            "crateVersion": env!("CARGO_PKG_VERSION"),
            "defaultFeatures": false,
            "features": ["redis"],
            "binding": "auth"
        },
        "compatibility": {
            "lensoRequirement": "^0.3.0",
            "hostApiRequirement": "^2.1.0",
            "consoleUiRequirement": "^2.0.0",
            "rustRequirement": ">=1.94"
        },
        "surfaceApi": {
            "contractDigest": crate::console_api::AUTH_CONTRACT_DIGEST,
            "operationIds": [
                crate::console_api::LIST_SESSIONS_OPERATION,
                crate::console_api::LIST_USERS_OPERATION,
                crate::console_api::REVOKE_SESSION_OPERATION,
                crate::console_api::DISABLE_USER_OPERATION,
                crate::console_api::ENABLE_USER_OPERATION
            ],
            "contractArtifact": {
                "format": "openapi_3_1_json",
                "document": AUTH_CONTRACT_DOCUMENT
            }
        }
    })
}

fn artifact_digest() -> String {
    let hex = Sha256::digest(AUTH_CONSOLE_ARTIFACT)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_template_binds_the_current_module_and_surface_contract() {
        let release = console_release_template();
        assert_eq!(release["moduleId"], "lenso/auth");
        assert_eq!(release["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            release["artifact"]["digest"],
            "sha256:01d607ec71232d7973cbce6787f4cd713f49eefb18002bf5764d65656708cf89"
        );
        assert_eq!(
            release["surfaceApi"]["contractDigest"],
            crate::console_api::AUTH_CONTRACT_DIGEST
        );
        assert_eq!(
            release["artifact"]["manifest"],
            serde_json::to_value(
                crate::module::manifest().console_module_manifest("^2.1.0", "^2.0.0")
            )
            .unwrap()
        );
    }
}
