create table if not exists auth_oauth.flows (
    state_hash text primary key,
    provider text not null,
    code_verifier text not null,
    return_to text not null,
    client_ip text,
    user_agent text,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    constraint flows_provider_not_empty check (length(provider) > 0),
    constraint flows_code_verifier_not_empty check (length(code_verifier) > 0),
    constraint flows_return_to_not_empty check (length(return_to) > 0)
);

create index if not exists flows_expires_at_idx on auth_oauth.flows (expires_at);
