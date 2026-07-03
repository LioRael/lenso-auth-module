create table if not exists auth_google.accounts (
    identity_id text primary key references auth.identities(id) on delete cascade,
    google_user_id text not null unique,
    display_name text not null,
    email text,
    picture_url text,
    updated_at timestamptz not null,
    constraint google_accounts_user_id_not_empty check (length(google_user_id) > 0),
    constraint google_accounts_display_name_not_empty check (length(display_name) > 0)
);
