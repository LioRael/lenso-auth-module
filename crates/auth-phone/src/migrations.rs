use platform_core::Migration;

pub const AUTH_PHONE_MIGRATIONS: &[Migration] = &[Migration {
    name: "auth-phone/0001_create_auth_phone_schema",
    sql: include_str!("../migrations/0001_create_auth_phone_schema.sql"),
}];
