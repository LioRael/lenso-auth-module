# ADR 0002: Use asymmetric assertions and owned API-token state

- Status: accepted
- Date: 2026-08-23
- Upstream: Lenso ADR 0039, ADR 0041, ADR 0042, and ADR 0064

## Context

The portable SDK originally signed `ActorAssertion` values with HMAC and gave
target Modules the same bytes for verification. A symmetric verifier can also
mint a valid assertion, so it is not verification-only authority and cannot be
the basis of a production Auth Module.

The first concrete vNext Auth workflow also needs durable credentials and
revocation without restoring the removed v0.3 platform, HTTP, Console, or
shared-database types.

## Decision

`ActorAssertionIssuer` signs with Ed25519. Auth alone resolves and holds the
private signing material. `ActorAssertionVerifier` is reconstructed from a
public key safe to place in immutable target configuration. The Capability wire
shape remains unchanged; its `proof` changes from an HMAC to an Ed25519
signature.

The first concrete Provider is `lenso-auth-api-token-module`:

- it accepts only protocol-neutral `bearer` evidence selected by an Adapter;
- it stores an HMAC digest of a random opaque token, never token plaintext;
- it owns private PostgreSQL session and token tables;
- it checks credential expiry and token/session revocation on every
  authentication;
- it issues short-lived, audience-limited assertions; and
- it resolves its database URL, signing key, and token pepper through one
  explicit Secrets binding during preparation.

Schema setup and upgrade plus token issuance and revocation are explicit owner
workflows. Preparation verifies the existing exact schema and never migrates.

## Consequences

- A target Module with a public verification key cannot forge Auth assertions.
- Credential or storage failure never falls back to anonymous or cached state.
- Revoking a token or session affects the next authentication; already-issued
  assertions remain valid only for their short bounded lifetime, as required by
  ADR 0039.
- The Module does not own HTTP extraction, Organization/RBAC authorization,
  OAuth, password policy, Console UI, or another Module's tables.
- The assertion proof-format change requires an SDK minor version bump before
  publication.
