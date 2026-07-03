use platform_core::Migration;

pub const AUTH_GITHUB_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-github/0001_create_auth_github_schema",
        sql: include_str!("../migrations/0001_create_auth_github_schema.sql"),
    },
    Migration {
        name: "auth-github/0002_create_github_accounts",
        sql: include_str!("../migrations/0002_create_github_accounts.sql"),
    },
];
