alter table auth.sessions
    add column if not exists device_id text;

create index if not exists sessions_device_id_idx on auth.sessions (device_id);
