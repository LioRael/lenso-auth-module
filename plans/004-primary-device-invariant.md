# Plan 004: Preserve exactly one primary device per subject

> Drift check: `git diff --stat b4a2f53..HEAD -- crates/lenso-auth-device-plugin`.

## Status

- **Priority**: P2
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `b4a2f53`, 2026-08-30

## Why this matters

The current transaction clears the old primary before confirming the requested device
exists, and concurrent assignments can create multiple primaries when none existed.

## Current state

- `src/lib.rs:154-163` clears every primary and then updates the target.
- `migrations/001_create_auth_devices.sql:1-14` lacks a partial unique constraint.

## Scope

In scope: device plugin source, an additive migration, and PostgreSQL acceptance tests.
Out of scope: trust semantics unrelated to primary selection.

## Steps

1. Test nonexistent-target preservation and two-connection concurrent primary writes.
2. Lock and verify the target before clearing/updating, returning `NotFound` without
   mutation.
3. Add a partial unique index on subject where `primary_at IS NOT NULL`, with a safe
   migration precondition for existing duplicates.

## Verification

- `lenso-cargo test -p lenso-auth-device-plugin --include-ignored` -> all pass with PostgreSQL.
- `lenso-cargo check -p lenso-auth-device-plugin --all-targets` -> exit 0.
- `git diff --check` -> no output.

## STOP conditions

Stop and report if existing fixture data contains duplicate primaries and the repo has
no documented deterministic survivor policy.
