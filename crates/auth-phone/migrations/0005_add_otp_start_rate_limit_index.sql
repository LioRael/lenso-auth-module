create index if not exists otp_challenges_client_ip_created_at_idx
    on auth_phone.otp_challenges (client_ip, created_at desc)
    where client_ip is not null;
