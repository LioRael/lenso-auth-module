alter table auth_password.login_failures
    add column if not exists last_failed_ip text,
    add column if not exists last_failed_user_agent text;
