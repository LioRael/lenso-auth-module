create table if not exists auth_oidc.authorization_codes (
    code_hash text primary key,
    user_id text not null references auth.users(id) on delete cascade,
    client_id text not null,
    redirect_uri text not null,
    scope text not null,
    code_challenge text not null,
    code_challenge_method text not null,
    nonce text,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint authorization_codes_client_id_not_empty check (length(client_id) > 0),
    constraint authorization_codes_redirect_uri_not_empty check (length(redirect_uri) > 0),
    constraint authorization_codes_scope_not_empty check (length(scope) > 0),
    constraint authorization_codes_code_challenge_not_empty check (length(code_challenge) > 0),
    constraint authorization_codes_code_challenge_method_not_empty check (length(code_challenge_method) > 0)
);

create index if not exists authorization_codes_expires_at_idx
    on auth_oidc.authorization_codes (expires_at);
