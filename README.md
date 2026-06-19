# Lenso Auth Module

First-party Lenso auth modules and Runtime Console surface.

- `crates/auth`: Rust linked auth module.
- `crates/auth-password`: Rust password provider module.
- `packages/auth-console`: Runtime Console surface loaded as a runtime bundle.

## Packages

- Rust: `lenso-module-auth`
- Rust: `lenso-module-auth-password`
- npm: `@lenso/auth-console`

## Development

```sh
cargo test --locked -p lenso-module-auth -p lenso-module-auth-password
pnpm install --frozen-lockfile
pnpm check
```

The console package treats `@lenso/runtime-console-api` as a peer dependency.
Local development resolves it from the sibling `lenso-runtime-console`
repository.
