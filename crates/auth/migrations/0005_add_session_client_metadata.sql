alter table auth.sessions
    add column if not exists client_ip text,
    add column if not exists user_agent text;
