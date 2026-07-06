# Auth Phone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a first-party `auth-phone` linked module that supports one phone identity with both phone password login and SMS OTP login.

**Architecture:** Keep `auth` as the identity/session anchor. Add `auth-phone` in `lenso-auth-module` as a provider module that owns phone normalization, OTP challenges, phone password credentials, and phone session routes while creating sessions through `auth::public`. After the module crate is tested, wire it through the sibling `lenso` repo as a builtin, OpenAPI-visible module, and official catalog entry.

**Tech Stack:** Rust 2024, Axum, SQLx/Postgres, Argon2, `auth::public` identity/session helpers, Lenso linked module manifests, Runtime Config descriptors, cargo tests.

## Global Constraints

- The durable module boundary is `auth-phone`, not `auth-otp`.
- `auth.identities.provider` must be `"phone"` and `provider_subject` must be canonical E.164.
- V1 accepts E.164 phone input directly; default-region parsing is not part of this plan.
- OTP codes must never be stored raw.
- OTP codes must not be returned outside explicit local development configuration.
- Public auth failures must not reveal whether a phone number exists.
- Successful session creation must use the existing auth session policy path.
- Anonymous upgrade must use `auth::public::link_identity_to_anonymous_user_in_tx`.
- KnowFlow frontend migration is not part of this plan; it gets a separate plan after `auth-phone` ships.

---

## File Structure

### `lenso-auth-module`

- Create: `crates/auth-phone/Cargo.toml`
- Create: `crates/auth-phone/migrations/0001_create_auth_phone_schema.sql`
- Create: `crates/auth-phone/migrations/0002_create_phone_identities.sql`
- Create: `crates/auth-phone/migrations/0003_create_otp_challenges.sql`
- Create: `crates/auth-phone/migrations/0004_create_password_credentials.sql`
- Create: `crates/auth-phone/migrations/0005_create_password_failures.sql`
- Create: `crates/auth-phone/src/admin.rs`
- Create: `crates/auth-phone/src/config.rs`
- Create: `crates/auth-phone/src/dto.rs`
- Create: `crates/auth-phone/src/lib.rs`
- Create: `crates/auth-phone/src/migrations.rs`
- Create: `crates/auth-phone/src/module.rs`
- Create: `crates/auth-phone/src/otp.rs`
- Create: `crates/auth-phone/src/password.rs`
- Create: `crates/auth-phone/src/phone.rs`
- Create: `crates/auth-phone/src/repositories.rs`
- Create: `crates/auth-phone/src/routes.rs`
- Create: `crates/auth-phone/tests/otp_flow.rs`
- Create: `crates/auth-phone/tests/password_flow.rs`
- Modify: `Cargo.toml`
- Modify: `README.md`

### `lenso`

- Modify: `/Users/leosouthey/Projects/framework/lenso/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-bootstrap/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-bootstrap/src/lib.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso/src/host.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/openapi_contract.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/admin_data_console.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/platform-admin-data/catalogs/lenso-official-module-catalog.json`
- Modify: `/Users/leosouthey/Projects/framework/lenso/docs/architecture/auth-module.md`
- Modify: `/Users/leosouthey/Projects/framework/lenso/README.md`

---

### Task 1: Add `auth-phone` Crate Skeleton And Manifest

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/auth-phone/Cargo.toml`
- Create: `crates/auth-phone/src/lib.rs`
- Create: `crates/auth-phone/src/module.rs`
- Create: `crates/auth-phone/src/migrations.rs`
- Create: `crates/auth-phone/migrations/0001_create_auth_phone_schema.sql`

**Interfaces:**
- Consumes: `auth::module::MODULE_NAME`
- Produces: `auth_phone::module::MODULE_NAME`, `auth_phone::module::manifest()`, `auth_phone::module::linked_module()`, `AUTH_PHONE_MIGRATIONS`

- [ ] **Step 1: Write the failing manifest test**

Create `crates/auth-phone/src/module.rs` with this test first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{ModuleManifestLintSeverity, ModuleSource, lint_module_manifest};

    #[test]
    fn manifest_declares_phone_routes_and_auth_dependency() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(
            manifest.dependencies,
            vec![auth::module::MODULE_NAME.to_owned()]
        );
        assert_eq!(manifest.http_routes, http_routes());

        let paths: Vec<_> = manifest
            .http_routes
            .iter()
            .map(|route| route.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec![
                "/v1/auth/phone/otp/start",
                "/v1/auth/phone/otp/verify",
                "/v1/auth/phone/password/set",
                "/v1/auth/phone/password/login",
            ]
        );

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-phone manifest should not have warning/error lints: {lints:?}"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone manifest_declares_phone_routes_and_auth_dependency
```

Expected: fails because package `lenso-module-auth-phone` does not exist.

- [ ] **Step 3: Add minimal crate and manifest implementation**

Add `auth-phone` to workspace members and dependencies in root `Cargo.toml`:

```toml
members = [
    "crates/auth",
    "crates/auth-anonymous",
    "crates/auth-device",
    "crates/auth-github",
    "crates/auth-google",
    "crates/auth-oauth",
    "crates/auth-oidc",
    "crates/auth-password",
    "crates/auth-phone",
]

auth-phone = { package = "lenso-module-auth-phone", path = "crates/auth-phone", version = "0.1.0" }
```

Create `crates/auth-phone/Cargo.toml`:

```toml
[package]
name = "lenso-module-auth-phone"
version = "0.1.0"
edition.workspace = true
license = "MIT"
description = "First-party phone auth provider module for the Lenso backend framework."
repository = "https://github.com/LioRael/lenso-auth-module"
homepage = "https://github.com/LioRael/lenso-auth-module"
readme = "../../README.md"
categories = ["web-programming", "development-tools"]
keywords = ["backend", "framework", "auth", "phone"]
rust-version.workspace = true

[lib]
name = "auth_phone"
path = "src/lib.rs"

[dependencies]
argon2.workspace = true
async-trait.workspace = true
auth.workspace = true
axum.workspace = true
chrono.workspace = true
getrandom.workspace = true
platform-core.workspace = true
platform-http.workspace = true
platform-module.workspace = true
serde.workspace = true
serde_json.workspace = true
sqlx.workspace = true
utoipa.workspace = true

[dev-dependencies]
platform-runtime.workspace = true
platform-testing.workspace = true
tokio.workspace = true
tower.workspace = true

[lints]
workspace = true
```

Create `crates/auth-phone/src/lib.rs`:

```rust
pub mod migrations;
pub mod module;
pub mod routes;
```

Create `crates/auth-phone/src/migrations.rs`:

```rust
use platform_core::Migration;

pub const AUTH_PHONE_MIGRATIONS: &[Migration] = &[Migration {
    name: "auth-phone/0001_create_auth_phone_schema",
    sql: include_str!("../migrations/0001_create_auth_phone_schema.sql"),
}];
```

Create `crates/auth-phone/migrations/0001_create_auth_phone_schema.sql`:

```sql
create schema if not exists auth_phone;
```

Create `crates/auth-phone/src/routes.rs`:

```rust
use platform_http::{ApiOpenApiRouter, OpenApiRouter};

pub fn router() -> ApiOpenApiRouter {
    OpenApiRouter::new()
}
```

Create `crates/auth-phone/src/module.rs`:

```rust
use crate::migrations::AUTH_PHONE_MIGRATIONS;
use platform_core::AppContext;
use platform_http::ApiOpenApiRouter;
use platform_module::{
    HostLinkedModule, LinkedBinding, LinkedHttpContribution, Module, ModuleHttpMethod,
    ModuleHttpRoute, ModuleManifest,
};

pub const MODULE_NAME: &str = "auth-phone";

pub fn http_routes() -> Vec<ModuleHttpRoute> {
    vec![
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/otp/start".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Start Phone OTP".to_owned()),
            story_title: Some("Phone OTP Start".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/otp/verify".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Verify Phone OTP".to_owned()),
            story_title: Some("Phone OTP Verify".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/password/set".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Set Phone Password".to_owned()),
            story_title: Some("Phone Password Set".to_owned()),
        },
        ModuleHttpRoute {
            method: ModuleHttpMethod::Post,
            path: "/v1/auth/phone/password/login".to_owned(),
            capability: None,
            operation: None,
            display_name: Some("Login With Phone Password".to_owned()),
            story_title: Some("Phone Password Login".to_owned()),
        },
    ]
}

pub fn manifest() -> ModuleManifest {
    ModuleManifest::builder(MODULE_NAME)
        .dependencies(vec![auth::module::MODULE_NAME.to_owned()])
        .http_routes(http_routes())
        .build()
}

pub fn merge_http(base: ApiOpenApiRouter) -> ApiOpenApiRouter {
    base.merge(crate::routes::router())
}

pub fn binding() -> LinkedBinding {
    LinkedBinding::builder()
        .http(LinkedHttpContribution {
            public_prefixes: &["/v1/auth/phone/"],
            merge: merge_http,
        })
        .build()
}

pub fn module(_ctx: &AppContext) -> Module {
    Module::linked(manifest(), binding())
}

pub fn linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(MODULE_NAME, manifest, module, AUTH_PHONE_MIGRATIONS)
        .with_http_binding(binding)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone manifest_declares_phone_routes_and_auth_dependency
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add Cargo.toml crates/auth-phone
git commit -m "feat: add auth-phone module skeleton"
```

---

### Task 2: Add Phone Normalization And Config Primitives

**Files:**
- Modify: `crates/auth-phone/src/lib.rs`
- Create: `crates/auth-phone/src/phone.rs`
- Create: `crates/auth-phone/src/config.rs`
- Create: `crates/auth-phone/src/password.rs`
- Create: `crates/auth-phone/src/otp.rs`

**Interfaces:**
- Produces: `normalize_phone_e164(phone: &str) -> AppResult<String>`
- Produces: `AuthPhoneConfig::from_context(ctx: &AppContext) -> AppResult<AuthPhoneConfig>`
- Produces: `hash_password`, `verify_password`, `validate_password`
- Produces: `hash_otp_code(code: &str, secret: &str) -> String`, `new_otp_code(length: usize) -> String`

- [ ] **Step 1: Write failing unit tests**

Create `crates/auth-phone/src/phone.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_trimmed_e164_phone_numbers() {
        assert_eq!(
            normalize_phone_e164("  +8613800000000  ").expect("phone should normalize"),
            "+8613800000000"
        );
    }

    #[test]
    fn rejects_non_e164_phone_numbers() {
        assert!(normalize_phone_e164("13800000000").is_err());
        assert!(normalize_phone_e164("+86 abc").is_err());
        assert!(normalize_phone_e164("+").is_err());
    }
}
```

Create `crates/auth-phone/src/otp.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_otp_code_is_numeric_with_requested_length() {
        let code = new_otp_code(6);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|char| char.is_ascii_digit()));
    }

    #[test]
    fn otp_hash_changes_with_secret() {
        let first = hash_otp_code("123456", "secret-one");
        let second = hash_otp_code("123456", "secret-two");

        assert_ne!(first, "123456");
        assert_ne!(first, second);
        assert_eq!(first, hash_otp_code("123456", "secret-one"));
    }
}
```

Create `crates/auth-phone/src/password.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthPhoneConfig;

    #[test]
    fn password_hash_verifies_original_password_only() {
        let config = AuthPhoneConfig::default();
        let hash = hash_password("correct horse", &config).expect("password should hash");

        assert!(verify_password(&hash, "correct horse").expect("hash should verify"));
        assert!(!verify_password(&hash, "wrong horse").expect("hash should verify"));
    }

    #[test]
    fn password_validation_uses_configured_min_length() {
        let config = AuthPhoneConfig {
            password_min_length: 10,
            ..AuthPhoneConfig::default()
        };

        assert!(validate_password("123456789", &config).is_err());
        assert!(validate_password("1234567890", &config).is_ok());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone phone::tests otp::tests password::tests
```

Expected: fails because the modules and functions are missing.

- [ ] **Step 3: Implement the primitives**

Add modules to `crates/auth-phone/src/lib.rs`:

```rust
pub mod config;
pub mod migrations;
pub mod module;
pub mod otp;
pub mod password;
pub mod phone;
pub mod routes;
```

Implement `crates/auth-phone/src/phone.rs`:

```rust
use platform_core::error::ErrorDetail;
use platform_core::{AppError, AppResult};

const MIN_E164_DIGITS: usize = 8;
const MAX_E164_DIGITS: usize = 15;

pub fn normalize_phone_e164(phone: &str) -> AppResult<String> {
    let trimmed = phone.trim();
    let digits = trimmed.strip_prefix('+').ok_or_else(|| validation_error("phone"))?;

    if digits.len() < MIN_E164_DIGITS
        || digits.len() > MAX_E164_DIGITS
        || !digits.chars().all(|char| char.is_ascii_digit())
        || digits.starts_with('0')
    {
        return Err(validation_error("phone"));
    }

    Ok(format!("+{digits}"))
}

fn validation_error(field: &str) -> AppError {
    AppError::validation(
        "Request validation failed",
        vec![ErrorDetail {
            field: Some(field.to_owned()),
            reason: "phone must be a canonical E.164 number".to_owned(),
        }],
    )
}
```

Implement `crates/auth-phone/src/config.rs` with defaults:

```rust
use platform_core::{AppContext, AppResult, RuntimeConfigDescriptor, RuntimeConfigGroupDescriptor};
use serde::Deserialize;
use std::sync::LazyLock;

pub const CONFIG_PREFIX: &str = "auth-phone";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthPhoneConfig {
    #[serde(default = "default_otp_code_length")]
    pub otp_code_length: usize,
    #[serde(default = "default_otp_ttl_seconds")]
    pub otp_ttl_seconds: i64,
    #[serde(default = "default_otp_resend_cooldown_seconds")]
    pub otp_resend_cooldown_seconds: i64,
    #[serde(default = "default_otp_max_attempts")]
    pub otp_max_attempts: i32,
    #[serde(default = "default_otp_secret")]
    pub otp_secret: String,
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
}

impl Default for AuthPhoneConfig {
    fn default() -> Self {
        Self {
            otp_code_length: default_otp_code_length(),
            otp_ttl_seconds: default_otp_ttl_seconds(),
            otp_resend_cooldown_seconds: default_otp_resend_cooldown_seconds(),
            otp_max_attempts: default_otp_max_attempts(),
            otp_secret: default_otp_secret(),
            password_min_length: default_password_min_length(),
        }
    }
}

impl AuthPhoneConfig {
    pub fn from_context(ctx: &AppContext) -> AppResult<Self> {
        ctx.runtime_config.snapshot().get(CONFIG_PREFIX)
    }
}

pub static RUNTIME_CONFIG_GROUPS: LazyLock<Vec<RuntimeConfigGroupDescriptor>> =
    LazyLock::new(Vec::new);

pub static RUNTIME_CONFIG: LazyLock<Vec<RuntimeConfigDescriptor>> = LazyLock::new(Vec::new);

fn default_otp_code_length() -> usize {
    6
}

fn default_otp_ttl_seconds() -> i64 {
    300
}

fn default_otp_resend_cooldown_seconds() -> i64 {
    60
}

fn default_otp_max_attempts() -> i32 {
    5
}

fn default_otp_secret() -> String {
    "local-development-auth-phone-otp-secret".to_owned()
}

fn default_password_min_length() -> usize {
    8
}
```

Implement `password.rs` by adapting the existing `auth-password` Argon2 helpers and using `config.password_min_length`.

Implement `otp.rs`:

```rust
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub fn new_otp_code(length: usize) -> String {
    let mut output = String::with_capacity(length);
    while output.len() < length {
        let mut byte = [0u8; 1];
        getrandom::fill(&mut byte).expect("OS randomness should be available");
        let digit = byte[0] % 10;
        output.push(char::from(b'0' + digit));
    }
    output
}

pub fn hash_otp_code(code: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b":");
    hasher.update(code.as_bytes());
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
```

Add `sha2.workspace = true` to `crates/auth-phone/Cargo.toml`.

- [ ] **Step 4: Run the tests to verify they pass**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone phone::tests otp::tests password::tests
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add Cargo.toml crates/auth-phone
git commit -m "feat: add auth-phone primitives"
```

---

### Task 3: Add Phone Migrations And Repository Storage

**Files:**
- Modify: `crates/auth-phone/src/lib.rs`
- Modify: `crates/auth-phone/src/migrations.rs`
- Create: `crates/auth-phone/src/repositories.rs`
- Create: `crates/auth-phone/tests/otp_flow.rs`
- Create: migration files `0002` through `0005`

**Interfaces:**
- Produces: `PhoneAuthRepository::start_otp(input) -> AppResult<PhoneOtpChallenge>`
- Produces: `PhoneAuthRepository::consume_otp(challenge_id, code, now, config) -> AppResult<Option<PhoneOtpChallenge>>`
- Produces: `PhoneOtpPurpose::{SignIn, PasswordSetup, PasswordReset}`

- [ ] **Step 1: Write the failing OTP storage test**

Create `crates/auth-phone/tests/otp_flow.rs`:

```rust
use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::repositories::{PhoneAuthRepository, PhoneOtpPurpose, StartOtpInput};
use chrono::{Duration, Utc};
use platform_core::ClientRequestMetadata;
use platform_testing::database::TestDatabase;

#[tokio::test]
async fn start_otp_stores_hashed_code_and_consume_once() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(pool.clone());
    let now = Utc::now();

    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000000",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_challenge_test".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
        })
        .await
        .expect("otp starts");

    assert_eq!(challenge.phone_e164, "+8613800000000");
    assert_eq!(challenge.expires_at, now + Duration::seconds(config.otp_ttl_seconds));
    assert_eq!(
        challenge.resend_after,
        now + Duration::seconds(config.otp_resend_cooldown_seconds)
    );

    let stored_hash: String =
        sqlx::query_scalar("select code_hash from auth_phone.otp_challenges where id = $1")
            .bind("phone_otp_challenge_test")
            .fetch_one(pool)
            .await
            .expect("stored hash");
    assert_ne!(stored_hash, challenge.debug_code.expect("local debug code"));

    let consumed = repo
        .consume_otp("phone_otp_challenge_test", "000000", now + Duration::seconds(1), &config)
        .await
        .expect("wrong code checked");
    assert!(consumed.is_none());

    let consumed = repo
        .consume_otp(
            "phone_otp_challenge_test",
            challenge.debug_code.as_deref().expect("debug code"),
            now + Duration::seconds(2),
            &config,
        )
        .await
        .expect("otp consumed")
        .expect("otp should match");
    assert_eq!(consumed.phone_e164, "+8613800000000");

    assert!(
        repo.consume_otp(
            "phone_otp_challenge_test",
            challenge.debug_code.as_deref().expect("debug code"),
            now + Duration::seconds(3),
            &config,
        )
        .await
        .expect("second consume checked")
        .is_none()
    );
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once
```

Expected: fails because migrations and repository types do not exist.

- [ ] **Step 3: Add migrations and repository**

Add SQL files matching the spec data model. Update `AUTH_PHONE_MIGRATIONS`:

```rust
pub const AUTH_PHONE_MIGRATIONS: &[Migration] = &[
    Migration {
        name: "auth-phone/0001_create_auth_phone_schema",
        sql: include_str!("../migrations/0001_create_auth_phone_schema.sql"),
    },
    Migration {
        name: "auth-phone/0002_create_phone_identities",
        sql: include_str!("../migrations/0002_create_phone_identities.sql"),
    },
    Migration {
        name: "auth-phone/0003_create_otp_challenges",
        sql: include_str!("../migrations/0003_create_otp_challenges.sql"),
    },
    Migration {
        name: "auth-phone/0004_create_password_credentials",
        sql: include_str!("../migrations/0004_create_password_credentials.sql"),
    },
    Migration {
        name: "auth-phone/0005_create_password_failures",
        sql: include_str!("../migrations/0005_create_password_failures.sql"),
    },
];
```

Implement `repositories.rs` with:

```rust
#[derive(Debug, Clone)]
pub struct PhoneAuthRepository {
    pool: DbPool,
    session_policy: std::sync::Arc<dyn AuthSessionPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneOtpPurpose {
    SignIn,
    PasswordSetup,
    PasswordReset,
}

#[derive(Debug)]
pub struct StartOtpInput<'a> {
    pub phone: &'a str,
    pub purpose: PhoneOtpPurpose,
    pub challenge_id: String,
    pub now: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
    pub client: ClientRequestMetadata,
}

#[derive(Debug, Clone)]
pub struct PhoneOtpChallenge {
    pub id: String,
    pub phone_e164: String,
    pub purpose: PhoneOtpPurpose,
    pub expires_at: DateTime<Utc>,
    pub resend_after: DateTime<Utc>,
    pub debug_code: Option<String>,
}
```

`start_otp` must insert `hash_otp_code(&code, &config.otp_secret)` and return `debug_code: Some(code)` only while the module has no production sender implementation. `consume_otp` must update `consumed_at` only when the challenge is unexpired, unconsumed, and the hash matches.

- [ ] **Step 4: Run the test to verify it passes**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone start_otp_stores_hashed_code_and_consume_once
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add crates/auth-phone
git commit -m "feat: add auth-phone otp storage"
```

---

### Task 4: Verify OTP Into Phone Identity Session

**Files:**
- Modify: `crates/auth-phone/src/repositories.rs`
- Modify: `crates/auth-phone/tests/otp_flow.rs`

**Interfaces:**
- Produces: `verify_otp_with_options(input) -> AppResult<Option<AuthSession>>`
- Consumes: `auth::public::create_user_identity_in_tx`
- Consumes: `auth::public::link_identity_to_anonymous_user_in_tx`
- Consumes: `auth::public::create_session_in_tx_with_policy`

- [ ] **Step 1: Write failing tests for session creation and anonymous upgrade**

Append to `crates/auth-phone/tests/otp_flow.rs`:

```rust
use auth::public::{AuthUserId, create_anonymous_user_identity_in_tx};
use auth_phone::repositories::VerifyOtpOptions;

#[tokio::test]
async fn verify_otp_creates_phone_identity_and_session() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, auth::migrations::AUTH_MIGRATIONS)
        .await
        .expect("auth migrations apply");
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("phone migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000000",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_session".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");

    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_session",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_otp".to_owned(),
            user_id: "usr_phone_otp".to_owned(),
            identity_id: "auth_identity_phone_otp".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("ios-device".to_owned()),
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert_eq!(session.user_id.0, "usr_phone_otp");
    assert_eq!(session.id, "sess_phone_otp");
    assert_eq!(session.device_id.as_deref(), Some("ios-device"));

    let provider_subject: String =
        sqlx::query_scalar("select provider_subject from auth.identities where id = $1")
            .bind("auth_identity_phone_otp")
            .fetch_one(pool)
            .await
            .expect("identity subject");
    assert_eq!(provider_subject, "+8613800000000");
}

#[tokio::test]
async fn verify_otp_links_anonymous_user_when_requested() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, auth::migrations::AUTH_MIGRATIONS)
        .await
        .expect("auth migrations apply");
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("phone migrations apply");

    let now = Utc::now();
    let mut tx = pool.begin().await.expect("tx");
    create_anonymous_user_identity_in_tx(
        &mut tx,
        AuthUserId("usr_anon_phone".to_owned()),
        "auth_identity_anon".to_owned(),
        "anonymous",
        "anonymous-subject",
        now,
    )
    .await
    .expect("anonymous user");
    tx.commit().await.expect("commit");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(pool.clone());
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000001",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_otp_link".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");

    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_otp_link",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_link".to_owned(),
            user_id: "usr_unused_new".to_owned(),
            identity_id: "auth_identity_phone_link".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: Some(AuthUserId("usr_anon_phone".to_owned())),
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert_eq!(session.user_id.0, "usr_anon_phone");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone verify_otp_creates_phone_identity_and_session verify_otp_links_anonymous_user_when_requested
```

Expected: fails because `verify_otp_with_options` does not exist.

- [ ] **Step 3: Implement OTP verification sessions**

Add:

```rust
#[derive(Debug)]
pub struct VerifyOtpOptions<'a> {
    pub challenge_id: &'a str,
    pub code: &'a str,
    pub session_id: String,
    pub user_id: String,
    pub identity_id: String,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub config: &'a AuthPhoneConfig,
    pub device_id: Option<String>,
    pub client: ClientRequestMetadata,
    pub link_anonymous_user_id: Option<AuthUserId>,
}
```

Implementation rule: consume the challenge first, then find existing `provider='phone'` identity by `phone_e164`. If found, create a session for that user. If not found and `link_anonymous_user_id` is present, link the phone identity to the anonymous user. If not found and no anonymous user is present, create a new user identity. Upsert `auth_phone.identities` in the same transaction.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone verify_otp_creates_phone_identity_and_session verify_otp_links_anonymous_user_when_requested
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add crates/auth-phone
git commit -m "feat: verify phone otp sessions"
```

---

### Task 5: Add Phone Password Set And Login

**Files:**
- Modify: `crates/auth-phone/src/repositories.rs`
- Create: `crates/auth-phone/tests/password_flow.rs`

**Interfaces:**
- Produces: `set_password(user_id, password, now, config) -> AppResult<bool>`
- Produces: `login_password_with_options(input) -> AppResult<Option<AuthSession>>`

- [ ] **Step 1: Write failing password tests**

Create `crates/auth-phone/tests/password_flow.rs`:

```rust
use auth_phone::config::AuthPhoneConfig;
use auth_phone::migrations::AUTH_PHONE_MIGRATIONS;
use auth_phone::repositories::{
    LoginPhonePasswordOptions, PhoneAuthRepository, PhoneOtpPurpose, SetPhonePasswordOptions,
    StartOtpInput, VerifyOtpOptions,
};
use chrono::{Duration, Utc};
use platform_core::ClientRequestMetadata;
use platform_testing::database::TestDatabase;

#[tokio::test]
async fn set_password_then_login_creates_session() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, auth::migrations::AUTH_MIGRATIONS)
        .await
        .expect("auth migrations apply");
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("phone migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(pool.clone());
    let now = Utc::now();
    let challenge = repo
        .start_otp(StartOtpInput {
            phone: "+8613800000002",
            purpose: PhoneOtpPurpose::SignIn,
            challenge_id: "phone_password_challenge".to_owned(),
            now,
            config: &config,
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("otp starts");
    let session = repo
        .verify_otp_with_options(VerifyOtpOptions {
            challenge_id: "phone_password_challenge",
            code: challenge.debug_code.as_deref().expect("debug code"),
            session_id: "sess_phone_password_verified".to_owned(),
            user_id: "usr_phone_password".to_owned(),
            identity_id: "auth_identity_phone_password".to_owned(),
            now: now + Duration::seconds(1),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata::default(),
            link_anonymous_user_id: None,
        })
        .await
        .expect("otp verifies")
        .expect("session created");

    assert!(
        repo.set_password(SetPhonePasswordOptions {
            user_id: &session.user_id,
            password: "correct horse",
            now: now + Duration::seconds(2),
            config: &config,
        })
        .await
        .expect("password set")
    );

    let password_session = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000002",
            password: "correct horse",
            session_id: "sess_phone_password_login".to_owned(),
            now: now + Duration::seconds(3),
            expires_at: now + Duration::hours(12),
            config: &config,
            device_id: Some("ios-device".to_owned()),
            client: ClientRequestMetadata::default(),
        })
        .await
        .expect("password login")
        .expect("session created");

    assert_eq!(password_session.user_id, session.user_id);
    assert_eq!(password_session.id, "sess_phone_password_login");
}

#[tokio::test]
async fn wrong_phone_password_records_failure_metadata() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, auth::migrations::AUTH_MIGRATIONS)
        .await
        .expect("auth migrations apply");
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("phone migrations apply");

    let config = AuthPhoneConfig::default();
    let repo = PhoneAuthRepository::new(pool.clone());
    let result = repo
        .login_password_with_options(LoginPhonePasswordOptions {
            phone: "+8613800000003",
            password: "wrong horse",
            session_id: "sess_wrong".to_owned(),
            now: Utc::now(),
            expires_at: Utc::now() + Duration::hours(12),
            config: &config,
            device_id: None,
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
        })
        .await
        .expect_err("wrong password should error");

    assert_eq!(result.code(), platform_core::ErrorCode::Unauthorized);

    let row: (i32, Option<String>, Option<String>) = sqlx::query_as(
        "select failed_count, last_failed_ip, last_failed_user_agent from auth_phone.password_failures where phone_e164 = $1",
    )
    .bind("+8613800000003")
    .fetch_one(pool)
    .await
    .expect("failure row");

    assert_eq!(row.0, 1);
    assert_eq!(row.1.as_deref(), Some("127.0.0.1"));
    assert_eq!(row.2.as_deref(), Some("test-agent"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone set_password_then_login_creates_session wrong_phone_password_records_failure_metadata
```

Expected: fails because password repository methods do not exist.

- [ ] **Step 3: Implement password repository methods**

Add `SetPhonePasswordOptions` and `LoginPhonePasswordOptions`. `set_password` must find the phone identity owned by the current `AuthUserId`, upsert `auth_phone.password_credentials`, and return `false` if no phone identity exists. `login_password_with_options` must normalize phone, check lockout, verify Argon2 hash, clear failures on success, record client metadata on failure, and create a session through `auth::public::create_session_with_policy`.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone set_password_then_login_creates_session wrong_phone_password_records_failure_metadata
```

Expected: pass.

- [ ] **Step 5: Commit**

```sh
git add crates/auth-phone
git commit -m "feat: add phone password auth"
```

---

### Task 6: Add HTTP Routes And DTOs

**Files:**
- Create: `crates/auth-phone/src/dto.rs`
- Modify: `crates/auth-phone/src/lib.rs`
- Modify: `crates/auth-phone/src/routes.rs`
- Modify: `crates/auth-phone/src/module.rs`
- Modify: `crates/auth-phone/tests/otp_flow.rs`
- Modify: `crates/auth-phone/tests/password_flow.rs`

**Interfaces:**
- Produces route handlers for `/v1/auth/phone/otp/start`, `/v1/auth/phone/otp/verify`, `/v1/auth/phone/password/set`, `/v1/auth/phone/password/login`
- Produces response DTOs `PhoneOtpStartResponse`, `PhonePasswordUpdatedResponse`, and `PhoneSessionResponse`

- [ ] **Step 1: Write failing route tests**

Append route-level tests using `tower::ServiceExt`:

```rust
#[tokio::test]
async fn otp_start_route_returns_challenge_without_raw_code() {
    let db = TestDatabase::new().await;
    let pool = db.pool();
    platform_testing::database::apply_migrations(pool, auth::migrations::AUTH_MIGRATIONS)
        .await
        .expect("auth migrations apply");
    platform_testing::database::apply_migrations(pool, AUTH_PHONE_MIGRATIONS)
        .await
        .expect("phone migrations apply");

    let ctx = platform_testing::app::test_app_context(pool.clone()).await;
    let (router, _) = auth_phone::routes::router().split_for_parts();
    let response = router
        .with_state(ctx)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/auth/phone/otp/start")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"phone":"+8613800000004","purpose":"sign_in"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(json["challenge_id"].as_str().is_some());
    assert!(json.get("code").is_none());
}
```

- [ ] **Step 2: Run route tests to verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone otp_start_route_returns_challenge_without_raw_code
```

Expected: fails because route handlers and DTOs are missing.

- [ ] **Step 3: Implement DTOs and routes**

Create `dto.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhoneOtpStartRequest {
    pub phone: String,
    pub purpose: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhoneOtpStartResponse {
    pub challenge_id: String,
    pub expires_at: DateTime<Utc>,
    pub resend_after: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhoneOtpVerifyRequest {
    pub challenge_id: String,
    pub code: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhonePasswordSetRequest {
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PhonePasswordLoginRequest {
    pub phone: String,
    pub password: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhonePasswordUpdatedResponse {
    pub updated: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PhoneSessionResponse {
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
}
```

Routes should follow `auth-password` patterns for `HttpRequestContext`, `AuthSessionPolicyHandle`, secure cookie, `ActorContext`, and `SESSION_COOKIE_NAME`.

- [ ] **Step 4: Run route and repository tests**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone
```

Expected: all `auth-phone` tests pass.

- [ ] **Step 5: Commit**

```sh
git add crates/auth-phone
git commit -m "feat: expose auth-phone routes"
```

---

### Task 7: Add Runtime Config, Admin Action, README

**Files:**
- Create: `crates/auth-phone/src/admin.rs`
- Modify: `crates/auth-phone/src/config.rs`
- Modify: `crates/auth-phone/src/lib.rs`
- Modify: `crates/auth-phone/src/module.rs`
- Modify: `README.md`

**Interfaces:**
- Produces runtime config groups/descriptors for `auth-phone`
- Produces `AuthPhoneAdminActions`
- Produces reset password admin action `reset_phone_password`

- [ ] **Step 1: Write failing manifest/config/admin tests**

Add to `module.rs` tests:

```rust
#[test]
fn manifest_declares_reset_phone_password_contribution() {
    let manifest = manifest();

    assert!(
        manifest
            .capabilities
            .iter()
            .any(|capability| capability == AUTH_PHONE_CREDENTIALS_WRITE)
    );
    assert_eq!(manifest.declarative_admin.actions.len(), 1);
    assert_eq!(manifest.declarative_admin.actions[0].name, RESET_PHONE_PASSWORD_ACTION);
    assert_eq!(manifest.console_contributions.len(), 1);
}
```

Add to `config.rs` tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_config_contains_auth_phone_keys() {
        let keys: Vec<_> = RUNTIME_CONFIG.iter().map(|descriptor| descriptor.key.as_str()).collect();

        assert!(keys.contains(&"auth-phone.otp_code_length"));
        assert!(keys.contains(&"auth-phone.otp_ttl_seconds"));
        assert!(keys.contains(&"auth-phone.password_min_length"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone manifest_declares_reset_phone_password_contribution runtime_config_contains_auth_phone_keys
```

Expected: fails because config descriptors and admin contribution are missing.

- [ ] **Step 3: Implement config descriptors and admin action**

Follow `auth-password` module patterns:

- capability constant: `auth_phone.credentials.write`;
- admin action name: `reset_phone_password`;
- user detail slot target: `auth::module::AUTH_USERS_DETAIL_ACTIONS_SLOT`;
- action input fields: `user_id`, `new_password`;
- `module()` registers runtime config groups, runtime config descriptors, and `with_admin_actions`.

Update `README.md` module list with:

```md
- `auth-phone`: first-party phone provider with phone password and SMS OTP flows.
```

- [ ] **Step 4: Run tests**

Run:

```sh
cargo test --locked -p lenso-module-auth-phone
```

Expected: all `auth-phone` tests pass.

- [ ] **Step 5: Commit**

```sh
git add crates/auth-phone README.md
git commit -m "feat: add auth-phone config and admin surfaces"
```

---

### Task 8: Wire `auth-phone` Through `lenso`

**Files:**
- Modify: `/Users/leosouthey/Projects/framework/lenso/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-bootstrap/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-bootstrap/src/lib.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso/src/host.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/Cargo.toml`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/openapi_contract.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/admin_data_console.rs`
- Modify: `/Users/leosouthey/Projects/framework/lenso/crates/platform-admin-data/catalogs/lenso-official-module-catalog.json`
- Modify: `/Users/leosouthey/Projects/framework/lenso/docs/architecture/auth-module.md`
- Modify: `/Users/leosouthey/Projects/framework/lenso/README.md`

**Interfaces:**
- Consumes: published or path-patched `auth-phone` crate
- Produces: `lenso_bootstrap::auth_phone_linked_module()`
- Produces: `lenso::host::builtins::auth_phone()`

- [ ] **Step 1: Write failing `lenso` tests**

In `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/openapi_contract.rs`, add:

```rust
#[test]
fn openapi_contains_auth_phone_contract() {
    let document = openapi_with_modules(|builder| {
        builder
            .with_linked_module(lenso_bootstrap::auth_linked_module())
            .with_linked_module(lenso_bootstrap::auth_phone_linked_module())
    });

    let paths = document.paths.paths;
    assert!(paths.contains_key("/v1/auth/phone/otp/start"));
    assert!(paths.contains_key("/v1/auth/phone/otp/verify"));
    assert!(paths.contains_key("/v1/auth/phone/password/set"));
    assert!(paths.contains_key("/v1/auth/phone/password/login"));
}
```

In `/Users/leosouthey/Projects/framework/lenso/crates/lenso-api/tests/admin_data_console.rs`, add assertions that official catalog includes `auth-phone` with `source == "linked"`.

- [ ] **Step 2: Run tests to verify they fail**

Run from `/Users/leosouthey/Projects/framework/lenso`:

```sh
cargo test --locked -p lenso-api --test openapi_contract openapi_contains_auth_phone_contract
```

Expected: fails because `auth_phone_linked_module` does not exist.

- [ ] **Step 3: Add builtin wiring**

Add workspace dependency in root `Cargo.toml`:

```toml
auth-phone = { package = "lenso-module-auth-phone", version = "0.1.0" }
```

Add patches while local development still points at the sibling checkout:

```toml
lenso-module-auth-phone = { git = "https://github.com/LioRael/lenso-auth-module.git", branch = "main" }
```

Add `auth-phone.workspace = true` to `crates/lenso-bootstrap/Cargo.toml` and `crates/lenso-api/Cargo.toml`.

Mirror the `auth_password_linked_module()` pattern in `crates/lenso-bootstrap/src/lib.rs`:

```rust
pub fn auth_phone_linked_module() -> HostLinkedModule {
    HostLinkedModule::linked(
        auth_phone::module::MODULE_NAME,
        auth_phone::module::manifest,
        auth_phone::module::module,
        auth_phone::migrations::AUTH_PHONE_MIGRATIONS,
    )
    .with_http_binding(auth_phone::module::binding)
}
```

Add `auth_phone_linked_module` to the builtin linked-module list, module metadata tests, runtime config tests, and uninstall/dependency tests wherever `auth-password` and `auth-anonymous` are already enumerated.

Expose in `crates/lenso/src/host.rs`:

```rust
pub use lenso_bootstrap::auth_phone_linked_module as auth_phone;
```

Add `auth-phone` to `crates/platform-admin-data/catalogs/lenso-official-module-catalog.json` with `manifestReference: "builtin:auth-phone"` and `source: "linked"`.

- [ ] **Step 4: Run focused `lenso` tests**

Run:

```sh
cargo test --locked -p lenso-bootstrap auth_phone
cargo test --locked -p lenso-api --test openapi_contract auth_phone
cargo test --locked -p lenso-api --test admin_data_console auth_phone
```

Expected: all focused tests pass.

- [ ] **Step 5: Commit in `lenso`**

```sh
cd /Users/leosouthey/Projects/framework/lenso
git add Cargo.toml crates/lenso-bootstrap crates/lenso crates/lenso-api crates/platform-admin-data docs README.md
git commit -m "feat: wire auth-phone builtin module"
```

---

### Task 9: Final Verification And Release Readiness

**Files:**
- Read-only unless generated files are updated by the repo commands.

**Interfaces:**
- Consumes all previous tasks.
- Produces verified local state ready for PR/release work.

- [ ] **Step 1: Run `lenso-auth-module` verification**

Run:

```sh
cd /Users/leosouthey/Projects/framework/lenso-auth-module
cargo test --locked -p lenso-module-auth -p lenso-module-auth-phone
cargo test --locked --workspace
git diff --check HEAD
```

Expected: cargo tests pass and `git diff --check` prints no errors.

- [ ] **Step 2: Run `lenso` verification**

Run:

```sh
cd /Users/leosouthey/Projects/framework/lenso
just generated-check
just arch-check
cargo test --locked -p lenso-bootstrap -p lenso-api -p lenso-platform-admin-data
git diff --check HEAD
```

Expected: generated checks, architecture check, cargo tests, and diff check pass.

- [ ] **Step 3: Manual smoke in generated or local host**

Start a host with `auth` and `auth-phone` linked. Run:

```sh
curl -sS -X POST http://127.0.0.1:3000/v1/auth/phone/otp/start \
  -H 'content-type: application/json' \
  -d '{"phone":"+8613800000000","purpose":"sign_in"}'
```

Expected: JSON includes `challenge_id`, `expires_at`, and `resend_after`, and does not include `code`.

Then use the local log sender output to verify:

```sh
curl -sS -X POST http://127.0.0.1:3000/v1/auth/phone/otp/verify \
  -H 'content-type: application/json' \
  -d '{"challenge_id":"<challenge_id>","code":"<logged_code>","device_id":"local-smoke"}'
```

Expected: JSON includes `user_id`, `session_id`, `token`, and `expires_at`.

- [ ] **Step 4: Document remaining release work**

If all checks pass, note the required release order:

```text
lenso-auth-module auth-phone crate -> lenso-bootstrap/lenso-api/lenso builtin update -> lenso-cli if templates or install profiles change
```

Commit any generated-contract updates in the repo that generated them.
