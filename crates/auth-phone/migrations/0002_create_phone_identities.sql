create unique index if not exists identities_id_provider_subject_key
    on auth.identities (id, provider, provider_subject);

create table if not exists auth_phone.identities (
    identity_id text primary key,
    provider text not null default 'phone',
    phone_e164 text not null unique,
    verified_at timestamptz not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    constraint phone_identities_phone_not_empty check (length(phone_e164) > 0),
    constraint phone_identities_provider_phone check (provider = 'phone'),
    constraint phone_identities_identity_contract_fkey
        foreign key (identity_id, provider, phone_e164)
        references auth.identities (id, provider, provider_subject)
        on delete cascade
);
