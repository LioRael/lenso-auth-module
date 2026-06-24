use platform_core::Migration;

pub const AUTH_OIDC_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-oidc/0001_create_auth_oidc_schema",
        sql: include_str!("../migrations/0001_create_auth_oidc_schema.sql"),
    },
    Migration {
        name: "auth-oidc/0002_create_authorization_codes",
        sql: include_str!("../migrations/0002_create_authorization_codes.sql"),
    },
];
