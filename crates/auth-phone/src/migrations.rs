use platform_core::Migration;

pub const AUTH_PHONE_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-phone/0001_create_auth_phone_schema",
        sql: include_str!("../migrations/0001_create_auth_phone_schema.sql"),
    },
    Migration {
        name: "auth-phone/0002_create_phone_identities",
        sql: include_str!("../migrations/0002_create_phone_identities.sql"),
    },
    Migration {
        name: "auth-phone/0003_create_otp_challenges",
        sql: include_str!("../migrations/0003_create_otp_challenges.sql"),
    },
    Migration {
        name: "auth-phone/0004_migrate_password_state_to_auth_password",
        sql: include_str!("../migrations/0004_migrate_password_state_to_auth_password.sql"),
    },
    Migration {
        name: "auth-phone/0005_add_otp_start_rate_limit_index",
        sql: include_str!("../migrations/0005_add_otp_start_rate_limit_index.sql"),
    },
];
