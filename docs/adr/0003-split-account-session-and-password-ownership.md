# ADR 0003: Split account, session, and password ownership

- Status: accepted
- Date: 2026-08-24
- Upstream: Lenso ADR 0064

## Context

Restoring the old Auth feature set as one package would couple canonical user
identity, credentials, authentication methods, wire protocols, and product
administration. Password login must be removable without deleting subjects or
preventing another authenticator from issuing a session.

## Decision

Introduce three portable request capabilities:

- `lenso.identity.directory@1` maps a provider-owned external subject to one
  canonical subject and exposes its active or disabled status;
- `lenso.auth.credential-issuer@1` issues and revokes opaque sessions for an
  active canonical subject; and
- `lenso.auth.password@1` registers and verifies password credentials.

`lenso-auth-account-module` implements the first two capabilities, verifies
`session` evidence for `lenso.auth@1`, and owns the identity and session schema.
Disabling a subject revokes every active session in the same transaction.

`lenso-auth-password-module` owns a separate schema containing Argon2id hashes
and bounded login-failure records. It calls Directory and Credential Issuer
through Plan-selected bindings and never writes the Account Module's tables.
Both modules resolve database locations through Secrets and require explicit
schema setup or upgrade before lifecycle preparation.

No HTTP endpoint, cookie policy, Web UI, Console, Organization membership, or
RBAC policy is part of these modules.

## Consequences

- Password login can be removed or replaced while subjects and sessions remain.
- OAuth, passkeys, recovery, and MFA can become peer Modules over the same
  Directory and Credential Issuer contracts.
- Registration spans two Module-owned stores. A storage failure after identity
  creation can leave an uncredentialed subject; retry is safe because identity
  creation is idempotent. Atomic cross-store registration is intentionally not
  claimed and can later use a workflow/outbox Module.
- `lenso.auth@1` still has an explicit single binding. Supporting multiple
  credential schemes for one caller requires a separately selected routing
  Module rather than implicit Kernel fallback.
