alter table auth_password.login_failures
    add column if not exists provider text not null default 'password';

alter table auth_password.login_failures
    drop constraint if exists login_failures_pkey;

alter table auth_password.login_failures
    add constraint login_failures_pkey primary key (provider, identifier);

create index if not exists login_failures_provider_locked_until_idx
    on auth_password.login_failures (provider, locked_until)
    where locked_until is not null;
