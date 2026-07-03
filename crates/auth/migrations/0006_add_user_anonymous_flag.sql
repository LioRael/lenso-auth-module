alter table auth.users
    add column if not exists is_anonymous boolean not null default false;

create index if not exists users_is_anonymous_idx
    on auth.users (is_anonymous)
    where is_anonymous;
