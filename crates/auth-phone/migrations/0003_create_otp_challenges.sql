create table if not exists auth_phone.otp_challenges (
    id text primary key,
    phone_e164 text not null,
    purpose text not null,
    code_hash text not null,
    attempts integer not null default 0,
    max_attempts integer not null,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    resend_after timestamptz not null,
    consumed_at timestamptz,
    client_ip text,
    user_agent text,
    constraint otp_phone_not_empty check (length(phone_e164) > 0),
    constraint otp_purpose_not_empty check (length(purpose) > 0),
    constraint otp_code_hash_not_empty check (length(code_hash) > 0),
    constraint otp_attempts_non_negative check (attempts >= 0),
    constraint otp_max_attempts_positive check (max_attempts > 0)
);

create index if not exists otp_challenges_phone_created_at_idx
    on auth_phone.otp_challenges (phone_e164, created_at desc);

create index if not exists otp_challenges_expires_at_idx
    on auth_phone.otp_challenges (expires_at);
