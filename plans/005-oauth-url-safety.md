# Plan 005: Reject unsafe OAuth endpoint configuration

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-federated-plugin`.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

The plugin sends the configured client secret to a token URL that is currently checked
only for parseability. Misconfiguration can send credentials over plaintext or to a
URL with misleading userinfo/fragment components.

## Current state

- `src/lib.rs:56-74` parses authorization, token, user, and redirect URLs only.
- `src/lib.rs:296-320` places the client secret in the token request body.

## Scope

In scope: federated plugin configuration validation and unit tests. Out of scope:
Host egress policy and redirect-flow redesign.

## Steps

1. Require HTTPS for outbound authorization/token/user endpoints; permit HTTP only for
   an explicit loopback development case already represented in config/tests.
2. Reject userinfo and fragments; apply redirect URI scheme rules separately so native
   app/custom schemes are not accidentally treated as outbound endpoints.
3. Add dangerous and valid configuration tests without real credentials.

## Verification

- `lenso-cargo test -p lenso-auth-federated-plugin` -> all pass.
- `lenso-cargo check -p lenso-auth-federated-plugin --all-targets` -> exit 0.

## STOP conditions

Stop if a shipped example relies on non-loopback plaintext OAuth; identify it rather
than adding a broad insecure escape hatch.
