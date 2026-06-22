use platform_core::Migration;

pub const AUTH_DEVICE_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-device/0001_create_auth_device_schema",
        sql: include_str!("../migrations/0001_create_auth_device_schema.sql"),
    },
    Migration {
        name: "auth-device/0002_add_device_client_metadata",
        sql: include_str!("../migrations/0002_add_device_client_metadata.sql"),
    },
];
