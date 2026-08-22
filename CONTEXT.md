# Lenso vNext Auth context

## Status

`main` owns the Lenso vNext Auth Capability Interface and portable assertion
semantics. It is not a compatibility workspace for the previously released
v0.3 Auth modules. That source remains on `v0.3`, in Git history, and under its
existing package tags.

## Interface

`lenso.auth@1` exposes one request Operation, `authenticate`:

- input: zero or one protocol-neutral credential selected by an ingress
  Adapter;
- success: `Absent` or `Authenticated(ActorAssertion)`;
- domain failures: invalid, expired, revoked, or unsupported credential; and
- runtime failures: unavailable Auth implementation or required state.

Credential material is sensitive. It never enters diagnostics, logs, App
Composition, or the assertion.

## Ownership

- Ingress Adapters own HTTP, cookie, WebSocket, game-protocol, and other wire
  credential selection policies.
- The bound Auth Module owns credential verification and signed assertion
  issuance.
- Auth-owned state includes sessions, credentials, and revocation knowledge
  when a concrete Module implements them.
- Target Modules own authorization and project a verified generic assertion
  into their own typed Actor.
- Kernel preserves sealed assertion provenance without interpreting Auth
  policy or credential material.

## Invariants

- There is no implicit global Auth chain or first-success fallback.
- Rejected selected credentials do not silently fall through to another
  credential.
- Assertions are issuer-bound, short-lived, audience-limited, and verified at
  the target seam.
- Delegation may narrow authority and validity but never widen them.
- Storage failure is a runtime failure and never produces anonymous identity.
- Concrete Auth implementations depend inward on the portable Kernel and
  Capability packages; portable Auth does not depend on an Adapter or product.
