# Lenso Auth Module

First-party Lenso auth modules and Runtime Console surface.

- `crates/auth`: Rust linked auth module.
- `crates/auth-anonymous`: Rust anonymous auth provider module.
- `crates/auth-device`: Rust linked auth device policy module.
- `crates/auth-github`: Rust GitHub OAuth provider module.
- `crates/auth-google`: Rust Google OAuth/OIDC provider module.
- `crates/auth-oauth`: Rust OAuth client substrate module.
- `crates/auth-oidc`: Rust OIDC provider module.
- `crates/auth-password`: Rust password provider module.
- `auth-phone`: first-party phone provider with phone password and SMS OTP flows (`crates/auth-phone`).
- `packages/auth-console`: Runtime Console surface loaded as a runtime bundle.

## Packages

- Rust: `lenso-module-auth`
- Rust: `lenso-module-auth-anonymous`
- Rust: `lenso-module-auth-device`
- Rust: `lenso-module-auth-github`
- Rust: `lenso-module-auth-google`
- Rust: `lenso-module-auth-oauth`
- Rust: `lenso-module-auth-oidc`
- Rust: `lenso-module-auth-password`
- Rust: `lenso-module-auth-phone`
- npm: `@lenso/auth-console`

## Redis Session Cache

`lenso-module-auth` resolves session tokens from Postgres by default. Hosts that
want Redis-backed session lookup should:

1. Depend on `lenso-module-auth` with `features = ["redis"]`.
2. Set `REDIS_URL` for the host process.
3. Set runtime config `auth.session_cache` to `redis`.

The runtime config key is module-owned and defaults to `database`. When it is
set to `redis`, the host must provide a Redis connection; otherwise Lenso fails
startup validation with a clear configuration error. Cached session keys use the
`auth:sessions:` prefix and expire at the lower of the session expiry and the
host's cache TTL.

Generated Lenso hosts can apply the matching descriptor profile with:

```sh
lenso module install auth --profile redis-session-cache
```

## JWT Secret

`lenso-module-auth-password` prefers the host's module-local
`LENSO_MODULE_AUTH_PASSWORD__JWT_SECRET` value for JWT signing. Runtime config
`auth-password.jwt_secret` remains a fallback for existing installs.

## Development

```sh
cargo test --locked -p lenso-module-auth -p lenso-module-auth-anonymous -p lenso-module-auth-device -p lenso-module-auth-github -p lenso-module-auth-google -p lenso-module-auth-oauth -p lenso-module-auth-oidc -p lenso-module-auth-password -p lenso-module-auth-phone
pnpm install --frozen-lockfile
pnpm check
```

The console package treats `@lenso/runtime-console-api` as a peer dependency.
Local development resolves it from the sibling `lenso-runtime-console`
repository.
