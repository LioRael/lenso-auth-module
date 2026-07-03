# Auth OAuth, GitHub, and Google Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable `auth-oauth` OAuth client substrate, then add first-party provider adapters such as `auth-github` and `auth-google`.

**Architecture:** Keep `auth` as the identity/session anchor. Add a thin `auth-oauth` linked module for shared state, PKCE, return-target validation, and one-time flow consumption. Add provider modules such as `auth-github` beside it; provider modules own remote provider quirks and call the shared substrate.

**Tech Stack:** Rust 2024, Axum, SQLx/Postgres, Lenso linked module manifests, existing `auth::public` helpers, focused cargo tests.

---

## Implementation Status

- Completed: `auth-oauth` crate, flow storage, PKCE S256, return target validation.
- Completed: `auth-github` crate, manifest/config, start route, callback route, fake-client callback test, account snapshot, normal Lenso session cookie.
- Completed: `auth-google` crate, Google OAuth/OIDC config, start route, callback route, fake-client callback test, account snapshot, normal Lenso session cookie.
- Verification command: `cargo test --locked -p lenso-module-auth -p lenso-module-auth-oauth -p lenso-module-auth-github -p lenso-module-auth-google`.

## Files

- Create: `crates/auth-oauth/Cargo.toml`
- Create: `crates/auth-oauth/migrations/0001_create_auth_oauth_schema.sql`
- Create: `crates/auth-oauth/migrations/0002_create_oauth_flows.sql`
- Create: `crates/auth-oauth/src/lib.rs`
- Create: `crates/auth-oauth/src/migrations.rs`
- Create: `crates/auth-oauth/src/module.rs`
- Create: `crates/auth-oauth/src/flow.rs`
- Create: `crates/auth-oauth/tests/flow.rs`
- Modify: `Cargo.toml`
- Modify: `README.md`
- Create: `crates/auth-github/*`
- Create: `crates/auth-google/*`

## Task 1: Add `auth-oauth` crate skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/auth-oauth/Cargo.toml`
- Create: `crates/auth-oauth/src/lib.rs`
- Create: `crates/auth-oauth/src/module.rs`
- Create: `crates/auth-oauth/src/migrations.rs`
- Create: `crates/auth-oauth/migrations/0001_create_auth_oauth_schema.sql`

- [ ] **Step 1: Write the failing manifest test**

Add this test in `crates/auth-oauth/src/module.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use platform_module::{ModuleManifestLintSeverity, ModuleSource, lint_module_manifest};

    #[test]
    fn manifest_declares_auth_dependency() {
        let manifest = manifest();

        assert_eq!(manifest.name, MODULE_NAME);
        assert_eq!(manifest.dependencies, vec![auth::module::MODULE_NAME]);

        let lints = lint_module_manifest(ModuleSource::Linked, &manifest);
        assert!(
            lints
                .iter()
                .all(|lint| lint.severity == ModuleManifestLintSeverity::Ok),
            "auth-oauth manifest should not have warning/error lints: {lints:?}"
        );
    }
}
```

- [ ] **Step 2: Run the test and verify it fails before implementation**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth manifest_declares_auth_dependency
```

Expected: fail because package `lenso-module-auth-oauth` does not exist.

- [ ] **Step 3: Add minimal crate and module implementation**

Add the crate to the workspace and workspace dependencies:

```toml
members = ["crates/auth", "crates/auth-device", "crates/auth-oauth", "crates/auth-oidc", "crates/auth-password"]

auth-oauth = { package = "lenso-module-auth-oauth", path = "crates/auth-oauth", version = "0.1.0" }
```

Create `crates/auth-oauth/src/module.rs` with `MODULE_NAME = "auth-oauth"`,
`manifest()` depending on `auth::module::MODULE_NAME`, `module()`, and
`linked_module()`.

- [ ] **Step 4: Run the test and verify it passes**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth manifest_declares_auth_dependency
```

Expected: pass.

## Task 2: Add OAuth flow storage

**Files:**
- Create: `crates/auth-oauth/migrations/0002_create_oauth_flows.sql`
- Create: `crates/auth-oauth/src/flow.rs`
- Create: `crates/auth-oauth/tests/flow.rs`

- [ ] **Step 1: Write the failing consume-once test**

Create `crates/auth-oauth/tests/flow.rs` with a database-backed test that:

```rust
#[tokio::test]
async fn consume_flow_returns_record_once() {
    let db = test_database().await;
    let pool = db.pool();
    apply_migrations(pool).await;
    let repo = OAuthFlowRepository::new(pool.clone());
    let now = Utc::now();

    let created = repo
        .create_flow(OAuthFlowInput {
            provider: "github".to_owned(),
            return_to: "/console".to_owned(),
            client: ClientRequestMetadata {
                ip: Some("127.0.0.1".to_owned()),
                user_agent: Some("test-agent".to_owned()),
            },
            created_at: now,
            expires_at: now + Duration::minutes(10),
        })
        .await
        .expect("flow created");

    let consumed = repo
        .consume_flow("github", &created.state, now + Duration::minutes(1))
        .await
        .expect("flow consumed")
        .expect("flow exists");

    assert_eq!(consumed.provider, "github");
    assert_eq!(consumed.return_to, "/console");
    assert_eq!(consumed.code_verifier, created.code_verifier);
    assert!(
        repo.consume_flow("github", &created.state, now + Duration::minutes(2))
            .await
            .expect("second consume checked")
            .is_none()
    );
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth consume_flow_returns_record_once
```

Expected: fail because `flow` types and storage do not exist.

- [ ] **Step 3: Implement the migration and repository**

Implement `auth_oauth.flows`, `OAuthFlowRepository`, `OAuthFlowInput`,
`OAuthCreatedFlow`, and `OAuthConsumedFlow`. Store only `state_hash`, not raw
state. Generate raw state with prefix `oauth_state_` and verifier with prefix
`oauth_verifier_`.

- [ ] **Step 4: Run the test and verify it passes**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth consume_flow_returns_record_once
```

Expected: pass.

## Task 3: Add PKCE and return target helpers

**Files:**
- Modify: `crates/auth-oauth/src/flow.rs`

- [ ] **Step 1: Write failing unit tests**

Add tests for:

```rust
#[test]
fn pkce_s256_matches_rfc_example() {
    assert_eq!(
        pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}

#[test]
fn return_to_accepts_only_safe_relative_targets() {
    assert_eq!(normalize_return_to(None).unwrap(), "/");
    assert_eq!(normalize_return_to(Some("/console?tab=modules")).unwrap(), "/console?tab=modules");
    assert!(normalize_return_to(Some("https://evil.example")).is_err());
    assert!(normalize_return_to(Some("//evil.example/path")).is_err());
    assert!(normalize_return_to(Some("/console#token")).is_err());
}
```

- [ ] **Step 2: Run tests and verify they fail**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth pkce_s256_matches_rfc_example return_to_accepts_only_safe_relative_targets
```

Expected: fail because helpers do not exist.

- [ ] **Step 3: Implement helpers**

Reuse the no-dependency base64url pattern already present in `auth-oidc`.
Keep `normalize_return_to` strict and small: relative path only, no fragment,
no protocol-relative target, no control characters.

- [ ] **Step 4: Run tests and verify they pass**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth
```

Expected: all `auth-oauth` tests pass.

## Task 4: Add README and workspace metadata

**Files:**
- Modify: `README.md`
- Modify: `Cargo.toml`

- [ ] **Step 1: Update README**

Document:

- `crates/auth-oauth`: Rust OAuth client substrate module.
- Rust package: `lenso-module-auth-oauth`.
- Dev command includes `-p lenso-module-auth-oauth`.

- [ ] **Step 2: Run focused checks**

Run:

```sh
cargo test --locked -p lenso-module-auth-oauth
cargo test --locked -p lenso-module-auth -p lenso-module-auth-oauth
```

Expected: pass.

## Task 5: Add `auth-github` provider adapter

**Files:**
- Create: `crates/auth-github/Cargo.toml`
- Create: `crates/auth-github/src/*`
- Create: `crates/auth-github/migrations/*`
- Modify: `Cargo.toml`
- Modify: `README.md`

- [ ] **Step 1: Start with config and manifest tests**

Test that `auth-github` depends on `auth` and `auth-oauth`, declares
`/v1/auth/github/start` and `/v1/auth/github/callback`, and validates required
module-local config.

- [ ] **Step 2: Add start-route tests**

Test that the start route creates an OAuth flow and redirects to GitHub with
`client_id`, `state`, `code_challenge`, `code_challenge_method=S256`, and
safe `return_to`.

- [ ] **Step 3: Add callback tests with fake client**

Test callback flow without live GitHub calls by injecting a small trait-backed
client. The test must prove provider subject is GitHub numeric user id and no
access token is stored.

- [ ] **Step 4: Implement minimal provider**

Use GitHub token/profile/email endpoints, then create or find
`auth.identities(provider='github')` and create a normal session response.

## Self-Review

- Spec coverage: `auth-oauth` covers shared OAuth safety; `auth-github` covers
  provider-specific mapping; `auth-oidc` naming conflict is explicitly avoided.
- Placeholder scan: no task relies on an unspecified "do the right thing" step.
- Type consistency: `OAuthFlowRepository`, `OAuthFlowInput`, `OAuthCreatedFlow`,
  and `OAuthConsumedFlow` are introduced before use by provider modules.
