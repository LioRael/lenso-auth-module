# Auth Phone Module Spec

## Goal

Add first-party phone authentication for Lenso apps. The first version supports
two user-facing sign-in methods for the same phone identity:

- phone + password login;
- phone + SMS one-time-code login.

The durable module boundary is `auth-phone`, not a standalone `auth-otp`
module. OTP is an authentication method for a phone identity. It should not
create a second identity namespace for the same phone number.

## Decision

Build a single `auth-phone` provider module.

`auth-phone` owns:

- phone number normalization;
- `auth.identities(provider = 'phone')` creation and lookup;
- SMS OTP challenge lifecycle;
- phone login sessions through the existing `auth` session helpers;
- anonymous-user upgrade by linking the phone identity to the current anonymous
  user when a bearer session is present.

`auth-phone` delegates password credentials, password hashing, password policy,
and password login failure tracking to `auth-password`.

`auth` continues to own users, identities, sessions, session cookies, actor
resolution, session cache, and session policy hooks.

## Approaches Considered

### Recommended: `auth-phone`

One module owns the phone identity and both authentication methods. This keeps
one phone number mapped to one `auth.identities` row and one user lifecycle.
Password login and OTP login share normalization, rate limits, device metadata,
anonymous upgrade, and admin/console surfaces.

### Rejected for v1: separate `auth-otp`

A generic OTP module is attractive too early. It would need to answer whether
`+8613800000000`, `leo@example.com`, TOTP, recovery codes, and magic links are
all the same abstraction. If used now, phone password and phone OTP could drift
into separate providers and force account-linking work later.

### Later: `auth-challenge` or `auth-otp` substrate

Extract a shared challenge substrate only after at least two concrete providers
need it, such as phone OTP and email OTP, or phone OTP and TOTP. That substrate
would own challenge hashing, expiry, attempts, and resend policy, while provider
modules still own subject normalization and identity mapping.

## Module Split

- `auth`: core user, identity, session, resolver, session policy, and session
  cache module.
- `auth-phone`: first-party phone provider module. Depends on `auth` and
  `auth-password`.
- `auth-password`: reusable password credential capability plus the existing
  generic identifier/password provider routes. It should not become
  phone-specific.
- Future SMS delivery adapters: out-of-process services or small sender
  adapters. They are delivery details, not identity providers.

## First Version Scope

`auth-phone` must provide:

- migrations for `auth_phone`;
- phone normalization to E.164;
- phone identity creation and lookup through `auth::public`;
- phone password setup and login through `auth-password`;
- SMS OTP start and verify;
- rate limiting for OTP challenges and provider-scoped password login failures;
- client metadata capture for failed attempts and sessions;
- session creation through the existing `auth` helpers;
- anonymous upgrade when the request actor is an anonymous user;
- linked module manifest, OpenAPI routes, runtime config, and docs.

`auth-phone` must not provide:

- email OTP;
- TOTP/authenticator app support;
- magic links;
- a generic challenge framework;
- encrypted long-term SMS provider credential storage beyond normal module
  config;
- a separate `otp` identity provider.

## HTTP API

### Start SMS OTP

`POST /v1/auth/phone/otp/start`

Request:

```json
{
  "phone": "+8613800000000",
  "purpose": "sign_in"
}
```

`purpose` is one of:

- `sign_in`;
- `password_setup`;
- `password_reset`.

Response:

```json
{
  "challenge_id": "phone_otp_challenge_...",
  "expires_at": "2026-07-07T08:00:00Z",
  "resend_after": "2026-07-07T07:56:00Z"
}
```

The response never includes the OTP code outside explicit local development
configuration.

### Verify SMS OTP

`POST /v1/auth/phone/otp/verify`

Request:

```json
{
  "challenge_id": "phone_otp_challenge_...",
  "code": "123456",
  "device_id": "ios-device-id"
}
```

Response uses the existing session response shape:

```json
{
  "user_id": "usr_...",
  "session_id": "sess_...",
  "token": "sess_...",
  "expires_at": "2026-07-07T20:00:00Z"
}
```

For `sign_in`, verification signs the user in or creates the phone identity when
it does not exist. For `password_setup` and `password_reset`, verification also
creates a normal session so the client can call password setup immediately under
that verified phone actor.

### Set Phone Password

`POST /v1/auth/phone/password/set`

Requires an authenticated phone actor. The caller must be signed in through the
same phone identity, usually after OTP verification.

Request:

```json
{
  "password": "correct horse battery staple"
}
```

Response:

```json
{
  "updated": true
}
```

This route creates or replaces the password credential for the current phone
identity. Admin reset remains a separate admin action, not this public route.

### Login With Phone Password

`POST /v1/auth/phone/password/login`

Request:

```json
{
  "phone": "+8613800000000",
  "password": "correct horse battery staple",
  "device_id": "ios-device-id"
}
```

Response uses the existing session response shape:

```json
{
  "user_id": "usr_...",
  "session_id": "sess_...",
  "token": "sess_...",
  "expires_at": "2026-07-07T20:00:00Z"
}
```

## Data Model

```sql
create schema if not exists auth_phone;
```

Phone identity metadata:

```sql
create table if not exists auth_phone.identities (
    identity_id text primary key references auth.identities(id) on delete cascade,
    phone_e164 text not null unique,
    verified_at timestamptz not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    constraint phone_identities_phone_not_empty check (length(phone_e164) > 0)
);
```

Password credential:

```sql
create table if not exists auth_password.credentials (
    identity_id text primary key references auth.identities(id) on delete cascade,
    password_hash text not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    constraint credentials_password_hash_not_empty check (length(password_hash) > 0)
);
```

Phone password credentials use the `auth.identities.id` for the phone identity.
They do not live in `auth_phone`.

OTP challenge:

```sql
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
```

Password failure tracking:

```sql
create table if not exists auth_password.login_failures (
    provider text not null,
    identifier text not null,
    failed_count integer not null,
    window_started_at timestamptz not null,
    last_failed_at timestamptz not null,
    locked_until timestamptz,
    last_failed_ip text,
    last_failed_user_agent text,
    primary key (provider, identifier),
    constraint login_failures_identifier_not_empty check (length(identifier) > 0),
    constraint login_failures_failed_count_positive check (failed_count > 0)
);
```

Phone password failures use `provider = 'phone'` and
`identifier = phone_e164`.

## Phone Normalization

V1 accepts E.164 input directly. Apps may enable a default region later, but the
stored subject must always be canonical E.164.

Identity mapping:

```text
auth.identities.provider = "phone"
auth.identities.provider_subject = phone_e164
```

All lookup, uniqueness, and rate-limit keys use the normalized E.164 value.

## Session And Anonymous Upgrade

OTP verification and password login create normal `auth` sessions. They must use
the existing session policy extension and `ClientRequestMetadata`.

When a request has an anonymous actor and the phone identity does not already
exist, `auth-phone` links the phone identity to that anonymous user through
`auth::public::link_identity_to_anonymous_user_in_tx`. This preserves app-owned
progress data already attached to the anonymous user.

If the phone identity already exists and the current actor is a different
anonymous user, verification signs into the existing phone user. Product data
merge remains app-owned.

## OTP Delivery Boundary

`auth-phone` owns challenge creation and verification. SMS delivery is a delivery
adapter.

V1 should include:

- `log` sender for local development only;
- `webhook` sender for production integration.

Webhook request:

```json
{
  "phone": "+8613800000000",
  "code": "123456",
  "purpose": "sign_in",
  "challenge_id": "phone_otp_challenge_..."
}
```

The webhook URL and authorization header come from module config. Provider
specific integrations such as Twilio, Aliyun, or Tencent Cloud can be added
later without changing the `auth-phone` identity model.

## Runtime Config

Initial config keys:

- `auth-phone.enabled`
- `auth-phone.otp_code_length`
- `auth-phone.otp_ttl_seconds`
- `auth-phone.otp_resend_cooldown_seconds`
- `auth-phone.otp_max_attempts`
- `auth-phone.otp_max_challenges_per_phone_per_hour`
- `auth-phone.otp_max_challenges_per_ip_per_hour`
- `auth-phone.sms_sender`
- `auth-phone.sms_webhook_url`
- `auth-phone.sms_webhook_authorization`

Password hash policy and password credential settings come from
`auth-password`. Password login failures are stored in
`auth_password.login_failures` with `provider = 'phone'`.

Defaults should be safe for local development and explicit for production.
Production must not use the local log sender unless the host is explicitly in a
local development environment.

## Security Rules

- Never store raw OTP codes.
- Hash OTP codes with a server-side secret or HMAC key.
- OTP challenges expire quickly, default 5 minutes.
- OTP challenges are single-use.
- Failed OTP attempts increment the challenge attempt count.
- OTP verification returns generic errors for invalid, expired, consumed, or
  mismatched challenges.
- OTP start applies per-phone and per-client-IP rate limits.
- Password login applies provider-scoped per-phone lockout with client metadata
  through `auth-password`.
- Public responses must not reveal whether a phone number already exists.
- Session cookies use the same secure-cookie policy as `auth-password`.
- All successful session creation goes through existing auth session policy.

## Runtime Console

V1 should expose the provider in the same provider console family as other auth
providers.

Minimum console/admin surfaces:

- provider card for `phone`;
- count of phone identities;
- count of recent OTP challenges;
- count of locked password login subjects;
- user detail contribution showing that the user has a phone identity;
- admin action to reset a phone password for a selected user.

Do not expose OTP codes in Runtime Console.

## Host And Release Wiring

The implementation must be carried through:

- `lenso-auth-module` new crate `crates/auth-phone`;
- workspace dependencies and tests;
- `lenso-bootstrap` install profile and feature wiring;
- `lenso::host::builtins::auth_phone()`;
- OpenAPI generation and generated contract checks;
- official catalog metadata and embedded official catalog snapshot;
- built-in module docs;
- release chain for crates that expose the new builtin.

## KnowFlow Integration

KnowFlow should move from `auth-password` to `auth-phone` after the module ships.
The frontend should replace the temporary `identifier` UI with phone input,
OTP start/verify, and password login. Learning-progress merge should remain
app-owned and continue to run after the phone session is activated.

## Testing Plan

Repository tests:

- manifest declares `auth-phone` dependency on `auth` and `auth-password`;
- migrations create the expected schema;
- OTP start stores a hashed code and never returns the code in production;
- OTP verify creates a session for a new phone identity;
- OTP verify signs into an existing phone identity;
- OTP verify links an anonymous user when appropriate;
- OTP verify rejects expired, consumed, and too-many-attempt challenges;
- password set requires an authenticated phone identity and stores the
  credential in `auth_password.credentials`;
- password login creates a session with the active session policy;
- password login records failure metadata and lockout;
- Runtime Console/admin data surfaces do not expose raw OTP values.

Smoke tests:

- start OTP with local log sender;
- verify OTP;
- set password;
- revoke session;
- login with phone password;
- verify `/v1/auth/sessions/revoke` still works for the phone session.

## Non-Goals

- No email OTP in v1.
- No TOTP/authenticator-app support in v1.
- No passkeys in v1.
- No generic `auth-otp` crate in v1.
- No vendor-specific SMS crate in v1.
- No app-level profile or progress data inside `auth-phone`.
