# Task 3 Report: Add Phone Migrations And Repository Storage

## What you implemented

- Added auth-phone migrations `0002` through `0005` for:
  - `auth_phone.identities`
  - `auth_phone.otp_challenges`
  - `auth_phone.password_credentials`
  - `auth_phone.password_failures`
- Expanded `AUTH_PHONE_MIGRATIONS` to include the new SQL files.
- Exported a new `repositories` module from `crates/auth-phone/src/lib.rs`.
- Implemented `PhoneAuthRepository` with:
  - `start_otp(StartOtpInput) -> AppResult<PhoneOtpChallenge>`
  - `consume_otp(challenge_id, code, now, config) -> AppResult<Option<PhoneOtpChallenge>>`
- Added `PhoneOtpPurpose::{SignIn, PasswordSetup, PasswordReset}` and Task 3 storage structs.
- Ensured `start_otp` stores only `hash_otp_code(&code, &config.otp_secret)` in `auth_phone.otp_challenges.code_hash`.
- Ensured `start_otp` returns `debug_code: Some(code)` for the current local-only sender phase.
- Ensured `consume_otp`:
  - returns `None` for missing, expired, consumed, or exhausted challenges
  - increments `attempts` on a wrong code without consuming the challenge
  - sets `consumed_at` only for an unexpired, unconsumed challenge under the attempts limit with a matching hash

## Tests and results

- `cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once`
  - Passed
- `cargo fmt`
  - Passed

## TDD Evidence

### RED command/output summary

Command:

```sh
cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once
```

Summary:

- Failed at compile time as expected before implementation.
- Initial failure:

```text
error[E0432]: unresolved import `auth_phone::repositories`
```

### GREEN command/output summary

Command:

```sh
cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once
```

Summary:

```text
test start_otp_stores_hashed_code_and_consume_once ... ok
test result: ok. 1 passed; 0 failed
```

## Files changed

- `crates/auth-phone/src/lib.rs`
- `crates/auth-phone/src/migrations.rs`
- `crates/auth-phone/src/repositories.rs`
- `crates/auth-phone/tests/otp_flow.rs`
- `crates/auth-phone/migrations/0002_create_phone_identities.sql`
- `crates/auth-phone/migrations/0003_create_otp_challenges.sql`
- `crates/auth-phone/migrations/0004_create_password_credentials.sql`
- `crates/auth-phone/migrations/0005_create_password_failures.sql`

## Self-review findings

- No functional issues found in the Task 3 slice after review.
- The integration test verifies the required storage behavior:
  - stored OTP is hashed, not raw
  - wrong-code attempt does not consume the challenge
  - correct code consumes once
  - second consume returns `None`
- Migration application order in the test uses:
  - `platform_core::PLATFORM_MIGRATIONS`
  - `auth::migrations::AUTH_MIGRATIONS`
  - `auth_phone::migrations::AUTH_PHONE_MIGRATIONS`

## Any concerns

- No blocking concerns for Task 3.

---

## Review Fix Follow-up: auth-phone OTP storage contract

### Findings fixed

- Added `return_debug_otp_code: bool` to `AuthPhoneConfig` with serde defaulting and a default value of `false`.
- Updated `PhoneAuthRepository::start_otp` to return `debug_code` only when `return_debug_otp_code` is enabled.
- Updated the Task 3 OTP flow test to explicitly enable debug OTP return when it needs to consume the generated code.
- Added a focused regression test proving the default config does not expose `debug_code`.
- Strengthened `auth_phone.identities` to anchor to the canonical auth identity contract by:
  - adding a unique index on `auth.identities (id, provider, provider_subject)`
  - adding a `provider text not null default 'phone'` column with a `provider = 'phone'` check
  - replacing the loose single-column FK with a composite FK `(identity_id, provider, phone_e164)` -> `(id, provider, provider_subject)`
- Added a focused integration test proving phone identity metadata rejects:
  - non-phone auth identities
  - phone identities whose `provider_subject` does not match `phone_e164`

### Tests and exact results

- `cargo fmt`
  - Passed
- `cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once`
  - Passed: `test start_otp_stores_hashed_code_and_consume_once ... ok`
- `cargo test --locked -p lenso-module-auth-phone start_otp_hides_debug_code_by_default`
  - Passed: `test start_otp_hides_debug_code_by_default ... ok`
- `cargo test --locked -p lenso-module-auth-phone phone_identity_metadata_rejects_non_phone_or_mismatched_subject`
  - Passed: `test phone_identity_metadata_rejects_non_phone_or_mismatched_subject ... ok`

### Files changed

- `crates/auth-phone/src/config.rs`
- `crates/auth-phone/src/repositories.rs`
- `crates/auth-phone/tests/otp_flow.rs`
- `crates/auth-phone/migrations/0002_create_phone_identities.sql`

### Any concerns

- No remaining concerns in the allowed Task 2/3 auth-phone slice.
