# ADR 0004: Restore authentication methods as removable Modules

- Status: accepted
- Date: 2026-08-24
- Upstream: Lenso ADR 0064

## Context

The v0.3 Auth workspace included anonymous, device, password, OAuth, GitHub,
Google, OIDC-provider, and phone behavior. Restoring those behaviors in one
package would merge product policy, private state, outbound transport, and
wire protocols. The vNext framework also requires App Composition to remain
the authority for selecting implementations.

## Decision

Restore each independently removable concern as a native Rust Module with a
portable request Capability:

- Anonymous Auth creates stable device-scoped anonymous subjects and asks the
  Account Module to issue sessions.
- Device Auth owns device metadata and trust facts.
- OAuth Flow owns expiring single-use state and AES-256-GCM-encrypted PKCE
  verifiers; only a keyed digest of OAuth state is stored.
- Federated Auth is installed as separate GitHub and Google instances. It uses
  a bound HTTP Client Capability for provider exchange/profile calls and the
  Directory and Credential Issuer capabilities for canonical identity.
- OIDC Provider owns authorization codes, stores only HMAC digests, requires
  PKCE S256, rechecks subject status, and signs ID tokens using a Secrets-owned
  RSA key. HTTP representation remains an Adapter concern.
- Phone Auth owns phone mappings, OTP challenges, Argon2id hashes, and bounded
  failure state. SMS delivery is an independently bound Capability.
- Auth Router maps each credential scheme to an explicitly named bound Auth
  provider. Unknown schemes fail and rejected credentials never fall through.

Every stateful Module keeps immutable SQL in its own `migrations/` directory
and declares the ordered plan with `lenso_postgres_kit::sql_migrations!`.
Explicit setup and upgrade operators use `SchemaOperator`; lifecycle
preparation uses `OwnedPostgres` to verify schema state and resolve logical
secrets but never creates or migrates storage.

## Consequences

- Any authentication method, the Router, or an outbound transport provider can
  be deleted from an App Plan without changing Kernel or the other Modules.
- Provider order cannot accidentally change credential policy: Router routes
  name provider instances rather than relying on binding insertion order.
- Cross-Module registration is idempotent but not transactionally atomic. A
  later workflow/outbox Module may coordinate recovery without moving state
  ownership into Kernel.
- HTTP endpoints, cookies, redirects, Web UI, and Console manifests remain
  separate work because they belong to Adapters or product targets.
