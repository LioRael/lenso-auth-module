do $$
begin
    if to_regclass('auth_phone.password_credentials') is not null then
        insert into auth_password.credentials (
            identity_id,
            password_hash,
            created_at,
            updated_at
        )
        select
            identity_id,
            password_hash,
            created_at,
            updated_at
        from auth_phone.password_credentials
        on conflict (identity_id) do update
        set password_hash = excluded.password_hash,
            updated_at = excluded.updated_at;
    end if;

    if to_regclass('auth_phone.password_failures') is not null then
        insert into auth_password.login_failures (
            provider,
            identifier,
            failed_count,
            window_started_at,
            last_failed_at,
            locked_until,
            last_failed_ip,
            last_failed_user_agent
        )
        select
            'phone',
            phone_e164,
            failed_count,
            window_started_at,
            last_failed_at,
            locked_until,
            last_failed_ip,
            last_failed_user_agent
        from auth_phone.password_failures
        on conflict (provider, identifier) do update
        set failed_count = excluded.failed_count,
            window_started_at = excluded.window_started_at,
            last_failed_at = excluded.last_failed_at,
            locked_until = excluded.locked_until,
            last_failed_ip = excluded.last_failed_ip,
            last_failed_user_agent = excluded.last_failed_user_agent;
    end if;
end $$;
