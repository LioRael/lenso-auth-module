create schema if not exists auth_device;

create table if not exists auth_device.devices (
    id text primary key,
    user_id text not null references auth.users(id) on delete cascade,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    trusted_at timestamptz,
    primary_at timestamptz
);

create index if not exists auth_device_devices_user_id_idx on auth_device.devices (user_id);
