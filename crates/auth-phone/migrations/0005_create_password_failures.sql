create table if not exists auth_phone.password_failures (
    phone_e164 text primary key,
    failed_count integer not null,
    window_started_at timestamptz not null,
    last_failed_at timestamptz not null,
    locked_until timestamptz,
    last_failed_ip text,
    last_failed_user_agent text,
    constraint phone_password_failures_phone_not_empty check (length(phone_e164) > 0),
    constraint phone_password_failures_count_positive check (failed_count > 0)
);
