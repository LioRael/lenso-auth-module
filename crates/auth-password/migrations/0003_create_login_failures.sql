create table if not exists auth_password.login_failures (
    identifier text primary key,
    failed_count integer not null,
    window_started_at timestamptz not null,
    last_failed_at timestamptz not null,
    locked_until timestamptz,
    constraint login_failures_identifier_not_empty check (length(identifier) > 0),
    constraint login_failures_failed_count_positive check (failed_count > 0)
);

create index if not exists login_failures_locked_until_idx
    on auth_password.login_failures (locked_until)
    where locked_until is not null;
