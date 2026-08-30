# Plan 003: Isolate Argon2 work and equalize invalid-credential cost

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-password-plugin crates/lenso-auth-phone-plugin`.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: `plans/002-atomic-auth-throttles.md`
- **Category**: perf
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

Argon2 hashing and verification currently execute synchronously inside native async
futures, blocking their execution lane. Missing credentials skip Argon2 entirely and
create a strong account-existence timing difference.

## Current state

- Password login at `lenso-auth-password-plugin/src/lib.rs:240-250` verifies only a
  loaded credential; helper functions at `395-409` run Argon2 synchronously.
- Phone password login and helpers repeat this at `397-413` and `607-617`.

## Scope

In scope: both plugins, their dependencies/config, and deterministic unit/load tests.
Out of scope: changing Argon2 parameters or credential hash formats.

## Steps

1. Introduce the repo/runtime-approved bounded blocking-work mechanism; cap concurrent
   and queued password jobs and return an existing bounded failure on overload.
2. Precompute or configure a valid dummy encoded hash and perform exactly one verify
   for credential misses as well as hits. Never log identifiers or hashes.
3. Inject/count the verifier in tests to prove equal work and test overload
   backpressure without wall-clock assertions.

## Verification

- Focused password and phone unit tests -> all pass.
- `lenso-cargo check -p lenso-auth-password-plugin -p lenso-auth-phone-plugin --all-targets` -> exit 0.
- `lenso-cargo test -p lenso-auth-password-plugin -p lenso-auth-phone-plugin` -> all pass.

## STOP conditions

Stop if the host runtime exposes no supported blocking-work facility and adding Tokio
would create a second executor. Report the runtime boundary instead of spawning
unbounded threads.
