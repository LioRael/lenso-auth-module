use platform_core::Migration;

pub const AUTH_GOOGLE_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-google/0001_create_auth_google_schema",
        sql: include_str!("../migrations/0001_create_auth_google_schema.sql"),
    },
    Migration {
        name: "auth-google/0002_create_google_accounts",
        sql: include_str!("../migrations/0002_create_google_accounts.sql"),
    },
];
