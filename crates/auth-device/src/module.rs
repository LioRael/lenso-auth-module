use crate::admin::AuthDeviceAdminData;
use crate::migrations::AUTH_DEVICE_MIGRATIONS;
use crate::policy::AuthDevicePolicy;
use crate::repositories::PostgresAuthDeviceRepository;
use auth::session_policy::{AuthHostExtension, AuthSessionPolicy};
use contracts::{ServiceOperationIdempotency, ServiceOperationMetadata};
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    AdminSchema, ConsoleNavigation, ConsoleSurface, ConsoleSurfacePresentation,
    ConsoleWorkspaceRef, EntitySchema, FieldSchema, FieldType, HostLinkedModule, LinkedBinding,
    LinkedHttpContribution, Module, ModuleHttpMethod, ModuleHttpRoute, ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth-device";
pub const AUTH_DEVICE_READ: &str = "auth_device.devices.read";

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![ModuleHttpRoute {
        method: ModuleHttpMethod::Get,
        path: "/v1/auth/device/console/devices".to_owned(),
        capability: Some(AUTH_DEVICE_READ.to_owned()),
        display_name: Some("List Auth Devices".to_owned()),
        story_title: Some("List Auth Devices".to_owned()),
        operation: Some(ServiceOperationMetadata {
            operation_id: Some(crate::console_api::LIST_DEVICES_OPERATION.to_owned()),
            summary: Some("List Auth Devices".to_owned()),
            idempotency: Some(ServiceOperationIdempotency::Idempotent),
            timeout_ms: Some(10_000),
            ..ServiceOperationMetadata::default()
        }),
    }]
}

fn auth_workspace() -> ConsoleWorkspaceRef {
    ConsoleWorkspaceRef {
        id: "auth".to_owned(),
        label: "Auth".to_owned(),
        icon: Some("shield".to_owned()),
    }
}

pub fn device_schema() -> AdminSchema {
    AdminSchema {
        entities: vec![EntitySchema {
            name: "devices".to_owned(),
            label: "Devices".to_owned(),
            read_capability: AUTH_DEVICE_READ.to_owned(),
            fields: vec![
                FieldSchema {
                    name: "id".to_owned(),
                    label: "ID".to_owned(),
                    field_type: FieldType::String,
                    nullable: false,
                },
                FieldSchema {
                    name: "user_id".to_owned(),
                    label: "User".to_owned(),
                    field_type: FieldType::String,
                    nullable: false,
                },
                FieldSchema {
                    name: "created_at".to_owned(),
                    label: "Created".to_owned(),
                    field_type: FieldType::Timestamp,
                    nullable: false,
                },
                FieldSchema {
                    name: "updated_at".to_owned(),
                    label: "Updated".to_owned(),
                    field_type: FieldType::Timestamp,
                    nullable: false,
                },
                FieldSchema {
                    name: "trusted_at".to_owned(),
                    label: "Trusted".to_owned(),
                    field_type: FieldType::Timestamp,
                    nullable: true,
                },
                FieldSchema {
                    name: "primary_at".to_owned(),
                    label: "Primary".to_owned(),
                    field_type: FieldType::Timestamp,
                    nullable: true,
                },
                FieldSchema {
                    name: "last_seen_ip".to_owned(),
                    label: "Last IP".to_owned(),
                    field_type: FieldType::String,
                    nullable: true,
                },
                FieldSchema {
                    name: "last_seen_user_agent".to_owned(),
                    label: "Last user agent".to_owned(),
                    field_type: FieldType::String,
                    nullable: true,
                },
            ],
        }],
    }
}

pub fn console_surfaces() -> Vec<ConsoleSurface> {
    vec![ConsoleSurface {
        name: "devices".to_owned(),
        label: "Devices".to_owned(),
        route: "/data/auth/devices".to_owned(),
        presentation: ConsoleSurfacePresentation::Esm {
            entry: "devices".to_owned(),
        },
        icon: Some("network".to_owned()),
        required_capabilities: vec![AUTH_DEVICE_READ.to_owned()],
        navigation: Some(ConsoleNavigation {
            workspace: auth_workspace(),
            group: None,
            order: Some(70),
        }),
    }]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .dependencies(vec![auth::module::MODULE_NAME.to_owned()])
        .capabilities(vec![AUTH_DEVICE_READ.to_owned()])
        .admin(device_schema())
        .console(console_surfaces())
        .http_routes(http_routes())
        .build()
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::console_api::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/device/console/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(ctx: &AppContext) -> Module {
    let repository = Arc::new(PostgresAuthDeviceRepository::new(ctx.db.clone()));
    Module::linked(manifest(), binding())
        .with_admin_data(Arc::new(AuthDeviceAdminData::new(repository)))
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUTH_DEVICE_MIGRATIONS)
        .with_contribution(AuthHostExtension::session_policy(auth_session_policy))
}

fn auth_session_policy(ctx: &AppContext) -> Arc<dyn AuthSessionPolicy> {
    Arc::new(AuthDevicePolicy::new(Arc::new(
        PostgresAuthDeviceRepository::new(ctx.db.clone()),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{AdminSurface, ModuleManifestLintSeverity};

    #[test]
    fn manifest_declares_device_admin_and_console_surface() {
        let manifest = manifest();

        assert_eq!(manifest.module_id, format!("lenso/{MODULE_NAME}"));
        assert_eq!(
            manifest
                .requires
                .iter()
                .map(|requirement| requirement
                    .module_id
                    .strip_prefix("lenso/")
                    .unwrap_or(&requirement.module_id)
                    .to_owned())
                .collect::<Vec<_>>(),
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.capabilities, vec![AUTH_DEVICE_READ.to_owned()]);
        assert_eq!(manifest.admin, Some(AdminSurface::Schema(device_schema())));
        assert_eq!(manifest.console, console_surfaces());

        let lints = platform_module::lint_module_manifest(&manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-device manifest should not have warning/error lints: {lints:?}"
        );
    }

    #[test]
    fn generated_console_manifest_matches_checked_in_artifact_manifest() {
        let generated =
            serde_json::to_value(manifest().console_module_manifest("^2.1.0", "^2.0.0"))
                .expect("console module manifest should serialize");
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../console-module.json"))
                .expect("console module manifest fixture should be valid JSON");

        assert_eq!(generated, checked_in);
    }
}
