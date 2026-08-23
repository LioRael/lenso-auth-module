# Lenso Auth Module

Portable Auth Capability contracts and assertion semantics for Lenso vNext.
The default `main` branch is vNext-only. The final mixed v0.3 workspace is
retained on the `v0.3` branch and by its existing package tags and releases.

## Workspace

- `crates/lenso-auth-api-token-module` is the first concrete Provider. It owns
  opaque API-token sessions, token/session revocation, assertion issuance, and
  a private PostgreSQL schema behind `lenso.auth@1`.
- `crates/lenso-capability-auth` owns the generated `lenso.auth@1` Capability
  Interface and its `authenticate` Operation.
- `crates/lenso-auth-sdk` owns protocol-neutral credential evidence, Auth
  outcomes, signed `ActorAssertion` issuance, verification, attenuation, and
  target-owned typed Actor projection.

The repository does not make HTTP headers, cookies, WebSocket handshakes, or
game frames part of the Auth Interface. Ingress Adapters select at most one
credential and call the Auth Capability. Target Modules authorize locally from
a verified, audience-limited assertion.

The API Token Module is deliberately narrow: it accepts only Adapter-selected
`bearer` evidence, stores only a keyed digest of each opaque token, checks
durable token/session revocation on every authentication, and issues a
short-lived Ed25519-signed assertion. Target Modules receive only the public
verification key and cannot mint assertions.

PostgreSQL setup, upgrade, token issuance, and revocation are explicit
operator workflows through `ApiTokenAuthOperator`. Module preparation resolves
the database URL, signing key, and token pepper through one explicitly bound
Secrets Capability and only verifies the existing schema. It never creates or
migrates state during App boot.

HTTP routes, cookies, Organization/RBAC policy, OAuth providers, password
flows, Console UI, and cross-Module database access are not part of this
Module. Future providers must remain behind the existing Capability Interface
and must not restore removed v0.3 platform types.

## API Token workflow

```rust,no_run
use std::collections::BTreeMap;
use lenso_auth_api_token_module::{ApiTokenAuthOperator, IssueApiToken};
use time::{Duration, OffsetDateTime};

# async fn example(database_url: &str, token_pepper: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
ApiTokenAuthOperator::setup(database_url, "auth_api").await?;
let operator = ApiTokenAuthOperator::connect(database_url, "auth_api").await?;
let issued = operator.issue(token_pepper, IssueApiToken {
    subject: "user-123".to_owned(),
    actor_kind: "user".to_owned(),
    assurance: "api-token".to_owned(),
    audience: vec!["orders.api@1:read".to_owned()],
    claims: BTreeMap::new(),
    expires_at: OffsetDateTime::now_utc() + Duration::days(30),
}).await?;

// Display this once. `Debug` redacts it and PostgreSQL stores only its HMAC digest.
let token = issued.expose_secret();
# let _ = token;
operator.revoke_session(issued.session_id()).await?;
# Ok(())
# }
```

The module currently uses pinned Git dependencies for the newly merged Secrets
Capability and PostgreSQL kit, so its crate remains `publish = false`. This is
an explicit release boundary, not a hidden fallback. Publish those dependencies
first, then replace the pins with registry versions before the first Module
release.

## Development

Run Cargo through the shared workspace wrapper when available:

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace
./scripts/check-repository-boundary.sh
```

Database acceptance additionally uses a disposable PostgreSQL instance:

```sh
LENSO_POSTGRES_TEST_URL=postgres://... \
  /Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo \
  test --locked --workspace -- --include-ignored --test-threads=1
```

The Capability descriptor is authoritative. Its build script rejects stale
Rust and TypeScript generated bindings.

## Branches

- `main`: Lenso vNext Auth Interface and portable semantics.
- `v0.3`: maintenance reference for the previously released v0.3 Auth modules.

Do not copy v0.3 crates or Console packages back into `main`. Reuse a behavior
only after naming its vNext Interface and owning Module or Adapter.
