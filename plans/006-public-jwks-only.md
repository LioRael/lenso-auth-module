# Plan 006: Validate and publish public JWK material only

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-oidc-plugin`.

## Status

- **Priority**: P3
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

OIDC configuration only checks that `keys` is an array, then publishes the full JSON.
Private RSA/EC members or unrelated top-level data can therefore be exposed by an
operator mistake.

## Current state

- `src/lib.rs:59-85` performs shallow JWKS validation.
- `src/lib.rs:176-190` clones and returns the configured object verbatim.

## Scope

In scope: OIDC provider config parsing, activation validation, JWKS response building,
and tests. Out of scope: changing signing-key storage or supported signing algorithms.

## Steps

1. Define strong public JWK types/validation for the algorithms actually used by this
   provider, requiring `kty`, `kid`, `use`/`alg` as applicable and public key members.
2. Reject private members (`d`, prime factors, private EC material) and duplicate key
   IDs during activation.
3. Reconstruct the JWKS response from validated public fields instead of cloning raw
   configuration. Add negative tests for private material and malformed keys.

## Verification

- `lenso-cargo test -p lenso-auth-oidc-plugin` -> all pass.
- `lenso-cargo check -p lenso-auth-oidc-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if configured key types exceed those the token signer/verifier actually supports;
list the mismatch instead of creating a permissive generic map.
