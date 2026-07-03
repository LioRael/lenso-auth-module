# Auth OAuth, GitHub, and Google Login Spec

## Goal

Add first-party OAuth login support without baking GitHub into the auth core.
`auth-oauth` provides the shared OAuth client substrate. `auth-github` and
`auth-google` are first-party provider adapters built on that substrate.

## Module Split

- `auth`: owns users, identities, sessions, session cookies, and actor
  resolution. Existing `auth.identities(provider, provider_subject)` remains the
  provider identity anchor.
- `auth-oauth`: owns outbound OAuth client flow safety: state, PKCE verifier,
  redirect return target validation, flow expiry, and one-time callback
  consumption.
- `auth-github`: owns GitHub-specific endpoints, configuration, profile/email
  mapping, and optional provider account snapshot.
- `auth-google`: owns Google-specific endpoints, configuration, OIDC userinfo
  mapping, and optional provider account snapshot.
- `auth-oidc`: keep as the current Lenso-as-OIDC-provider module. Do not reuse
  that name for inbound third-party login.
- Future `auth-oidc-client`: add only when multiple OIDC client providers need
  shared ID token validation beyond provider-specific userinfo lookup.

## First Version Scope

Build `auth-oauth` first, then provider modules such as `auth-github` and
`auth-google`.

`auth-oauth` must provide:

- `auth_oauth.flows` migration.
- `OAuthFlowRepository::create_flow`.
- `OAuthFlowRepository::consume_flow`.
- PKCE S256 helper and random verifier generation.
- `return_to` validation that accepts relative paths and rejects absolute URLs,
  protocol-relative URLs, control characters, and fragments.
- linked module manifest that depends on `auth`.

`auth-github` must provide:

- `GET /v1/auth/github/start`.
- `GET /v1/auth/github/callback`.
- module-local config for `client_id`, `client_secret`, and optional
  `allowed_return_to_prefixes`.
- GitHub profile mapping using GitHub numeric user id as
  `provider_subject`.
- session creation through existing auth session helpers.
- no access-token persistence in v1.

`auth-google` must provide:

- `GET /v1/auth/google/start`.
- `GET /v1/auth/google/callback`.
- module-local config for `client_id`, `client_secret`, optional
  `redirect_uri`, and endpoint overrides.
- default Google auth endpoints:
  `https://accounts.google.com/o/oauth2/v2/auth`,
  `https://oauth2.googleapis.com/token`, and
  `https://openidconnect.googleapis.com/v1/userinfo`.
- default scope `openid profile email`.
- Google `sub` as `provider_subject`.
- email mapping only when `email_verified` is true.
- session creation through existing auth session helpers.
- no access-token persistence in v1.

## Security Rules

- Always use PKCE S256.
- Store `state_hash`, never raw state.
- Flow TTL is 10 minutes.
- Consume callback flow once.
- Reject callback if state is absent, expired, consumed, or provider mismatches.
- Reject unsafe `return_to`; default to `/` when omitted.
- Do not persist third-party OAuth access tokens in v1.

## Data Model

`auth-oauth`:

```sql
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
```

`auth-github`:

```sql
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
```

`auth-google`:

```sql
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
```

## Provider Flow

1. `/v1/auth/github/start` validates config and `return_to`.
2. `auth-github` calls `auth-oauth` to create a flow.
3. `auth-github` redirects to GitHub authorize URL with `state`,
   `code_challenge`, and `code_challenge_method=S256`.
4. GitHub redirects back with `code` and `state`.
5. `auth-github` consumes the flow through `auth-oauth`.
6. `auth-github` exchanges code for token using the stored verifier.
7. `auth-github` loads GitHub user data.
8. `auth-github` finds or creates `auth.identities(provider='github')`.
9. A normal Lenso session is created and the response redirects to `return_to`.

`auth-google` follows the same substrate flow, but exchanges against Google's
token endpoint and loads the user profile from the OIDC userinfo endpoint.

## Non-Goals

- No dynamic provider registry in v1.
- No encrypted third-party access-token storage in v1.
- No generalized OIDC client until two or more inbound OIDC providers share
  enough ID-token validation logic to justify it.
- No remote-module OAuth hook in v1; these are first-party linked auth modules.
