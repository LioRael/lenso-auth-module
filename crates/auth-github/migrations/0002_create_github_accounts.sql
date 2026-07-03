create table if not exists auth_github.accounts (
    identity_id text primary key references auth.identities(id) on delete cascade,
    github_user_id text not null unique,
    login text not null,
    email text,
    avatar_url text,
    updated_at timestamptz not null,
    constraint github_accounts_user_id_not_empty check (length(github_user_id) > 0),
    constraint github_accounts_login_not_empty check (length(login) > 0)
);
