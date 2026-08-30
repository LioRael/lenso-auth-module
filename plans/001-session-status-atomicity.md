# Plan 001: Make effective subject status and session issuance atomic

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-account-plugin/src/storage.rs crates/lenso-auth-account-plugin/src/lib.rs crates/lenso-auth-account-plugin/tests`.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

Temporary disable expiry is interpreted differently by issuance and authentication,
and session insertion is not serialized with disable-and-revoke. This can create an
immediately unusable session or a session inserted after the revocation update.

## Current state

- `storage.rs:75-83` computes effective status for issuance.
- `storage.rs:138-158` returns the raw joined subject status during authentication.
- `lib.rs:318-341` checks and inserts through separate pool operations.
- `lib.rs:518-545` disables and revokes in a transaction.

## Scope

In scope: account storage/plugin source, SQL migration only if a schema helper is
strictly required, and account PostgreSQL acceptance tests. Out of scope: token wire
format, subject registration, or Router fallback behavior.

## Steps

1. Add acceptance tests for expired temporary disable, issue-versus-disable
   concurrency, and reactivation after disable.
2. Centralize one SQL effective-status expression used by both issuance and session
   loading.
3. Begin issuance transaction, lock the subject row, validate effective status, and
   insert the session before commit so disable and issuance serialize.

## Verification

- `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test -p lenso-auth-account-plugin --include-ignored` -> all pass with configured PostgreSQL.
- `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check -p lenso-auth-account-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if the acceptance database is unavailable after unit-level work; report the exact
unrun test command. Do not weaken locking to make a mock pass.
