use crate::admin::AuthDeviceAdminData;
use crate::migrations::AUTH_DEVICE_MIGRATIONS;
use crate::policy::AuthDevicePolicy;
use crate::repositories::PostgresAuthDeviceRepository;
use auth::session_policy::{AuthHostExtension, AuthSessionPolicy};
use platform_core::AppContext;
use platform_module::{
    AdminSchema, EntitySchema, FieldSchema, FieldType, HostLinkedModule, LinkedBinding, Module,
    ModuleManifest,
};
use std::sync::Arc;

pub const MODULE_NAME: &str = "auth-device";
pub const AUTH_DEVICE_READ: &str = "auth_device.devices.read";

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

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .dependencies(vec![auth::module::MODULE_NAME.to_owned()])
        .capabilities(vec![AUTH_DEVICE_READ.to_owned()])
        .admin(device_schema())
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
