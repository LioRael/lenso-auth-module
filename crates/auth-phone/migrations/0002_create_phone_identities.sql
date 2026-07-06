create table if not exists auth_phone.identities (
    identity_id text primary key references auth.identities(id) on delete cascade,
    phone_e164 text not null unique,
    verified_at timestamptz not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    constraint phone_identities_phone_not_empty check (length(phone_e164) > 0)
);
