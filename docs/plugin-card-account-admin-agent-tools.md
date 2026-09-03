# Auth Account Admin Agent Tools Plugin

## Product job

Let an explicitly configured Console Agent inspect canonical Auth subjects and
sessions, and enable or disable a subject through the Auth owner's existing
administration boundary.

## Contract and capabilities

- Plugin id: `lenso.auth.account-admin.agent-tools`
- Root slot: `tool-providers`
- Provides: `lenso.agent.tool-provider@2`
- Requires exactly one: `lenso.auth.account-admin@1`
- Configuration: none
- Lifecycle: none
- State and resources: none

The catalog provides two parallel-safe reads, `auth_account_admin_list_subjects`
and `auth_account_admin_list_sessions`, plus the exclusive
`auth_account_admin_set_subject_status` mutation. The adapter reuses the
Capability's generated request types and locked request Schemas.

## Authorization and sensitive data

The bound Account Admin provider remains final authorization authority through
its configured `admin_callers`. The adapter does not inspect Account storage or
weaken that caller check. It never exposes `lenso.auth@1`, password, phone,
federated, OIDC, API-token, or Credential Issuer operations. Subject and
session summaries contain no credential material.

Disabling a subject uses the Account owner's existing atomic behavior, which
also revokes that subject's active sessions. Re-enabling a subject does not
restore revoked sessions.

## Ownership and deletion boundary

The Account Auth Plugin remains the sole owner of subjects, sessions, status,
revocation, and authorization policy. This adapter owns only the Agent Tool
catalog and invocation translation. Removing it removes Agent access without
changing Auth facts, authentication behavior, or any credential.

## First observable behavior

When the Plugin is attached to a Console Agent and bound to an authorized
Account Admin provider, the Agent catalog contains exactly three Auth account
administration Tools. An unauthorized caller receives `PermissionDenied` from
the provider-owned check; malformed arguments and missing subjects remain
distinct Tool errors.
