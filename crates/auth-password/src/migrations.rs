use platform_core::Migration;

pub const AUTH_PASSWORD_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-password/0001_create_auth_password_schema",
        sql: include_str!("../migrations/0001_create_auth_password_schema.sql"),
    },
    Migration {
        name: "auth-password/0002_create_password_credentials",
        sql: include_str!("../migrations/0002_create_password_credentials.sql"),
    },
    Migration {
        name: "auth-password/0003_create_login_failures",
        sql: include_str!("../migrations/0003_create_login_failures.sql"),
    },
    Migration {
        name: "auth-password/0004_add_login_failure_client_metadata",
        sql: include_str!("../migrations/0004_add_login_failure_client_metadata.sql"),
    },
    Migration {
        name: "auth-password/0005_scope_login_failures_by_provider",
        sql: include_str!("../migrations/0005_scope_login_failures_by_provider.sql"),
    },
];
