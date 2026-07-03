use crate::admin::AuthDeviceAdminData;
use crate::migrations::AUTH_DEVICE_MIGRATIONS;
use crate::policy::AuthDevicePolicy;
use crate::repositories::PostgresAuthDeviceRepository;
use auth::session_policy::{AuthHostExtension, AuthSessionPolicy};
use platform_core::AppContext;
use platform_module::{
    AdminSchema, ConsoleArea, ConsoleNavigation, ConsolePackage, ConsoleSurface,
    ConsoleWorkspaceRef, EntitySchema, FieldSchema, FieldType, HostLinkedModule, LinkedBinding,
    Module, ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth-device";
pub const AUTH_DEVICE_READ: &str = "auth_device.devices.read";

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
        area: ConsoleArea::Data,
        route: "/data/auth/devices".to_owned(),
        package: ConsolePackage {
            name: "@lenso/auth-device-console".to_owned(),
            export: "authDeviceConsoleModule".to_owned(),
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
        .build()
}

pub fn module(ctx: &AppContext) -> Module {
    let repository = Arc::new(PostgresAuthDeviceRepository::new(ctx.db.clone()));
    Module::linked(manifest(), LinkedBinding::builder().build())
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
    use platform_module::{AdminSurface, ModuleManifestLintSeverity, ModuleSource};

    #[test]
    fn manifest_declares_device_admin_and_console_surface() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(
            manifest.dependencies,
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.capabilities, vec![AUTH_DEVICE_READ.to_owned()]);
        assert_eq!(manifest.admin, Some(AdminSurface::Schema(device_schema())));
        assert_eq!(manifest.console, console_surfaces());

        let lints = platform_module::lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-device manifest should not have warning/error lints: {lints:?}"
        );
    }
}
