# Plan 002: Enforce authentication throttles atomically in PostgreSQL

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-password-plugin crates/lenso-auth-phone-plugin`.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

OTP starts and password failures use count-then-insert, so concurrent callers can all
pass an old count and exceed configured limits. An absent client IP also removes the
cross-phone OTP limit entirely.

## Current state

- `lenso-auth-phone-plugin/src/lib.rs:166-193` checks IP and resend state before insert.
- `lenso-auth-phone-plugin/src/lib.rs:382-413` counts phone login failures before insert.
- `lenso-auth-password-plugin/src/lib.rs:229-250` repeats the same pattern.
- Current migrations contain query indexes but no atomic rate bucket.

## Scope

In scope: password/phone plugin source, additive migrations, config validation if a
fallback bucket is needed, and PostgreSQL concurrency tests. Out of scope: distributed
in-memory limits or accepting untrusted forwarded-IP headers.

## Steps

1. Add multi-connection tests that release more requests simultaneously than the
   configured limit and assert exactly the limit is admitted.
2. Implement durable keyed buckets or stable transaction-scoped keyed locks so
   decision and increment are one atomic operation. Use trusted IP when present and a
   bounded fallback key when it is absent.
3. Preserve resend cooldown, failure clearing after successful login, and existing
   domain error shapes.

## Verification

- `lenso-cargo test -p lenso-auth-password-plugin -p lenso-auth-phone-plugin --include-ignored` using the mandated wrapper -> all pass.
- `lenso-cargo check -p lenso-auth-password-plugin -p lenso-auth-phone-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop if the solution requires trusting a caller-supplied IP not already authenticated
by ingress, or if it weakens the limit at a window boundary.
