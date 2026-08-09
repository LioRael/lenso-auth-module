# Lenso Auth Module

First-party Lenso auth modules and verified Console UI ESM artifacts.

- `crates/auth`: Rust linked auth module.
- `crates/auth-anonymous`: Rust anonymous auth provider module.
- `crates/auth-device`: Rust linked auth device policy module.
- `crates/auth-github`: Rust GitHub OAuth provider module.
- `crates/auth-google`: Rust Google OAuth/OIDC provider module.
- `crates/auth-oauth`: Rust OAuth client substrate module.
- `crates/auth-oidc`: Rust OIDC provider module.
- `crates/auth-password`: Rust password credential module and identifier/password provider.
- `auth-phone`: first-party phone provider with SMS OTP flows and phone password routes backed by `auth-password` (`crates/auth-phone`).
- `packages/auth-console`: `lenso/auth` Console UI ESM artifact.
- `packages/auth-device-console`: `lenso/auth-device` Console UI ESM artifact.
- `packages/auth-oauth-console`: `lenso/auth-oauth` Console UI ESM artifact.
- `packages/auth-github-console`: `lenso/auth-github` Console UI ESM artifact.
- `packages/auth-google-console`: `lenso/auth-google` Console UI ESM artifact.
- `packages/auth-oidc-console`: `lenso/auth-oidc` Console UI ESM artifact.
- `packages/auth-provider-console`: shared provider surface source used by the four owning artifacts; it is not a Module Release artifact.

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

Each Console UI package emits an immutable `console_ui_esm` entry point and its
Rust-owned `console-module.json` manifest. The artifact is bound to the owning
Module Release; shared provider source does not create a family-level release
identity. Runtime data, actions, inventory, and contributions use the public
Console Module API and the explicit Managed Service Context supplied by the
Console host.
