# Lenso Auth Module

Portable Auth Capability contracts and assertion semantics for Lenso vNext.
The default `main` branch is vNext-only. The final mixed v0.3 workspace is
retained on the `v0.3` branch and by its existing package tags and releases.

## Workspace

- `crates/lenso-capability-auth` owns the generated `lenso.auth@1` Capability
  Interface and its `authenticate` Operation.
- `crates/lenso-auth-sdk` owns protocol-neutral credential evidence, Auth
  outcomes, signed `ActorAssertion` issuance, verification, attenuation, and
  target-owned typed Actor projection.

The repository does not make HTTP headers, cookies, WebSocket handshakes, or
game frames part of the Auth Interface. Ingress Adapters select at most one
credential and call the Auth Capability. Target Modules authorize locally from
a verified, audience-limited assertion.

Concrete credential stores, session and revocation state, OAuth providers,
databases, HTTP routes, and Console UI are not present on `main`. A future Auth
Module implementation must own those rules and state behind the existing
Capability Interface; it must not restore the removed v0.3 platform types.

## Development

Run Cargo through the shared workspace wrapper when available:

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace
./scripts/check-repository-boundary.sh
```

The Capability descriptor is authoritative. Its build script rejects stale
Rust and TypeScript generated bindings.

## Branches

- `main`: Lenso vNext Auth Interface and portable semantics.
- `v0.3`: maintenance reference for the previously released v0.3 Auth modules.

Do not copy v0.3 crates or Console packages back into `main`. Reuse a behavior
only after naming its vNext Interface and owning Module or Adapter.
