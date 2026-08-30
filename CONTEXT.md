# Lenso vNext Auth context

## Status

`main` owns the Lenso vNext Auth Capability Interface, portable assertion
semantics, and concrete vNext Auth Providers. It is not a compatibility
workspace for the previously released v0.3 Auth modules. That source remains
on `v0.3`, in Git history, and under its existing package tags.

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
- The bound Auth Plugin owns credential verification and signed assertion
  issuance.
- Auth-owned state includes sessions, credentials, and revocation knowledge
  when a concrete Plugin implements them.
- Target Plugins own authorization and project a verified generic assertion
  into their own typed Actor.
- Kernel preserves sealed assertion provenance without interpreting Auth
  policy or credential material.

## Invariants

- There is no implicit global Auth chain or first-success fallback.
- Rejected selected credentials do not silently fall through to another
  credential.
- Assertions are issuer-bound, short-lived, audience-limited, Ed25519-signed,
  and verified from public authority at the target seam.
- Delegation may narrow authority and validity but never widen them.
- Storage failure is a runtime failure and never produces anonymous identity.
- Concrete Auth implementations depend inward on the portable Kernel and
  Capability packages; portable Auth does not depend on an Adapter or product.

## Concrete Providers

`lenso-auth-api-token-plugin` owns random opaque API tokens, durable sessions,
token/session revocation, and its private PostgreSQL schema. It resolves only
logical Secrets references during preparation. Setup, upgrade, issuance, and
revocation are explicit operator workflows; preparation never migrates.

`lenso-auth-account-plugin` owns the canonical identity directory and opaque
user sessions. It provides Directory and Credential Issuer capabilities as
well as session evidence verification through `lenso.auth@1`.

`lenso-auth-password-plugin` owns only password hashes and login-throttling
state. It obtains subjects and sessions through explicit Directory and
Credential Issuer bindings. Removing it therefore removes password login but
does not remove identities or invalidate the account/session data model.

`lenso-auth-anonymous-plugin` creates a stable device-scoped anonymous identity
and session without owning canonical subjects. `lenso-auth-device-plugin` owns
device observation and trust facts behind its own administration Capability.

`lenso-auth-oauth-flow-plugin` owns single-use OAuth state, OIDC nonce custody,
and encrypted PKCE verifiers. The nonce is returned only with the same
successfully consumed state record. `lenso-auth-federated-plugin` is a
provider-keyed implementation for GitHub and Google instances; it obtains
outbound protocol transport through an explicit HTTP Client binding and
obtains identities and sessions through the shared contracts.

`lenso-auth-oidc-client-plugin` is the external OIDC relying party. It provides
the existing Federated Capability, validates RS256 ID tokens against configured
issuer, audience, JWKS key, time, and nonce constraints, and delegates identity
and session ownership to the same Directory and Credential Issuer contracts.
It does not own callback HTTP routes, cookies, or CSRF response policy.

`lenso-auth-web-session-plugin` is a separate HTTP Endpoint Adapter over one
bound Federated provider. It owns the fixed browser start/callback/logout
routes and response Cookie policy, but no identity, OAuth flow, or session
storage. Its logout handler receives only the credential evidence already
selected by Web Ingress and calls Credential Issuer 1.1 `revoke_credential`.
Web Ingress remains responsible for selecting the session Cookie, rejecting
credential ambiguity, enforcing double-submit CSRF on unsafe methods, and
stripping Cookie/CSRF headers before Endpoint dispatch.

`lenso-auth-oidc-plugin` remains the protocol-neutral authorization-code
issuer/provider. It
owns single-use HMAC-digested codes, requires PKCE S256, rechecks subject
status, and signs ID tokens from a Secrets-provided RSA key. Adapters may expose
its metadata, JWKS, authorization, and exchange operations over a wire format.

`lenso-auth-phone-plugin` owns normalized phone mappings, OTP challenges,
Argon2id phone-password hashes, and bounded failure records. SMS transport is a
separate bound `lenso.message.sms@1` Capability. Debug OTP disclosure is
configuration-valid only in the development environment.

When API-token and session authentication are both installed, App Composition
selects the intended `lenso.auth@1` provider for each caller. The optional
`lenso-auth-router-plugin` maps credential schemes to explicitly named, bound
provider instances. It never performs first-success fallback, and the Kernel
does not synthesize an Auth chain.
