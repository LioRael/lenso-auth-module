alter table auth_device.devices
    add column if not exists last_seen_ip text,
    add column if not exists last_seen_user_agent text;
