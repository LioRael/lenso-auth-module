use platform_core::Migration;

pub const AUTH_OAUTH_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-oauth/0001_create_auth_oauth_schema",
        sql: include_str!("../migrations/0001_create_auth_oauth_schema.sql"),
    },
    Migration {
        name: "auth-oauth/0002_create_oauth_flows",
        sql: include_str!("../migrations/0002_create_oauth_flows.sql"),
    },
];
