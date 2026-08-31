# Lenso Auth Plugin

Portable Auth Capability contracts and assertion semantics for Lenso vNext.
The default `main` branch is vNext-only. The final mixed v0.3 workspace is
retained on the `v0.3` branch and by its existing package tags and releases.

## Workspace

- `crates/lenso-auth-api-token-plugin` is the first concrete Provider. It owns
  opaque API-token sessions, token/session revocation, assertion issuance, and
  a private PostgreSQL schema behind `lenso.auth@1`.
- `crates/lenso-capability-auth` owns the generated `lenso.auth@1` Capability
  Interface and its `authenticate` Operation.
- `crates/lenso-auth-sdk` owns protocol-neutral credential evidence, Auth
  outcomes, signed `ActorAssertion` issuance, verification, attenuation, and
  target-owned typed Actor projection.

The repository does not make HTTP headers, cookies, WebSocket handshakes, or
game frames part of the Auth Interface. Ingress Adapters select at most one
credential and call the Auth Capability. Target Plugins authorize locally from
a verified, audience-limited assertion. The optional Auth Web Session Plugin is
an HTTP Endpoint Adapter over those contracts; it does not add Cookie semantics
to the portable Auth domain.

The API Token Plugin is deliberately narrow: it accepts only Adapter-selected
`bearer` evidence, stores only a keyed digest of each opaque token, checks
durable token/session revocation on every authentication, and issues a
short-lived Ed25519-signed assertion. Target Plugins receive only the public
verification key and cannot mint assertions.

PostgreSQL setup, upgrade, token issuance, and revocation are explicit
operator workflows through `ApiTokenAuthOperator`. Plugin preparation resolves
the database URL, signing key, and token pepper through one explicitly bound
Secrets Capability and only verifies the existing schema. It never creates or
migrates state during App boot.

Organization/RBAC policy, Console UI, and cross-Plugin database access are not
part of these Plugins. Apart from the explicitly named Web Session Adapter,
Auth Plugins remain wire-neutral and behind explicit Capabilities; they must
not restore removed v0.3 platform types.

`lenso-auth-oidc-client-plugin` is an external OpenID Connect relying party. It
adds a nonce to the single-use OAuth Flow record, performs authorization-code
exchange with PKCE, validates an RS256 ID token against the configured issuer,
client audience, JWKS key, expiry, issued-at time, and nonce, then obtains the
canonical subject and opaque session from bound Directory and Credential
Issuer providers. It is separate from `lenso-auth-oidc-plugin`, which makes a
Lenso App an OIDC issuer.

`lenso-auth-web-session-plugin` is the removable browser Adapter over a bound
Federated provider. It owns fixed OIDC start/callback/logout HTTP routes,
revalidates App-local return targets, emits `Secure`, `HttpOnly`,
`SameSite=Lax` opaque session Cookies plus a readable double-submit CSRF Cookie,
and revokes the Ingress-selected session credential on logout. Web Ingress owns
Cookie credential selection and rejects unsafe Cookie-authenticated requests
without matching CSRF evidence before the Endpoint runs. Account Auth remains
the only session store.

Credential Issuer 1.1 also allows an Adapter to revoke the selected opaque
session credential without first exposing or recovering its session id.

For Web composition, configure Auth Web Session and Web Ingress with identical
session and CSRF Cookie names. Configure a dedicated Ingress CSRF header name;
browser code copies the readable CSRF Cookie value into that header on unsafe
requests. The shipped routes are `/auth/oidc/start`, `/auth/oidc/callback`, and
`/auth/logout`.

## API Token workflow

```rust,no_run
use std::collections::BTreeMap;
use lenso_auth_api_token_plugin::{ApiTokenAuthOperator, IssueApiToken};
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

The workspace currently uses pinned Git dependencies for the newly merged Secrets
Capability and PostgreSQL kit, so its crate remains `publish = false`. This is
an explicit release boundary, not a hidden fallback. Publish those dependencies
first, then replace the pins with registry versions before the first Plugin
release.

## Development

Run Cargo through the shared workspace wrapper when available:

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
```

Database acceptance additionally uses a disposable PostgreSQL instance:

```sh
LENSO_POSTGRES_TEST_URL=postgres://... \
  cargo \
  test --locked --workspace -- --include-ignored --test-threads=1
```

Each Capability's annotated Rust trait and value types are the authoring
source. Its build script rejects stale locked Descriptor, Schema, and Rust
projection artifacts. For an intentional contract change, update the Rust
source, run the package once with `LENSO_UPDATE_CONTRACT_SNAPSHOT=1`, review
the locked snapshot diff, and regenerate `src/generated.rs` with
`lenso-contract-codegen 0.6.3`. Bun consumers import the matching TypeScript
projection from `@lenso/bun`, which locks the source revision independently.

Native Auth Plugins use `#[lenso::plugin]`; package identity, linked Factory,
and registration are generated from Cargo metadata. Stateful lifecycle and
explicit Capability endpoints remain Plugin-owned implementation details.

## Branches

- `main`: Lenso vNext Auth Interface and portable semantics.
- `v0.3`: maintenance reference for the previously released v0.3 Auth modules.

Do not copy v0.3 crates or Console packages back into `main`. Reuse a behavior
only after naming its vNext Interface and owning Plugin or Adapter.
