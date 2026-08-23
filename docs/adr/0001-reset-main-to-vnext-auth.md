# ADR 0001: Reset the default branch to vNext Auth ownership

- Status: accepted
- Date: 2026-08-22
- Upstream: Lenso ADR 0039 and ADR 0064

## Context

The repository previously owned the v0.3 linked Auth modules, provider crates,
database migrations, HTTP routes, and Console artifacts. Repository extraction
then added the vNext Auth Capability and SDK to the same workspace without
removing the old release line. Physical co-location mixed two incompatible
runtime vocabularies, dependency directions, and release surfaces.

## Decision

The default `main` branch owns only the vNext Auth Capability Interface and its
portable assertion semantics. The final mixed v0.3 tree is retained on the
`v0.3` branch, in Git history, and by immutable package tags and releases.

The vNext Auth seam follows upstream ADR 0039:

- an ingress Adapter selects protocol-specific credential evidence;
- a bound Auth Module implements `lenso.auth@1/authenticate`;
- Auth returns an absent outcome, a signed ActorAssertion, a domain failure, or
  a runtime failure; and
- each target Module verifies and authorizes the assertion locally.

No v0.3 compatibility shim or `legacy/` directory is added. HTTP, PostgreSQL,
Redis, OAuth provider, Console, and product policy may return only through a
new vNext Module or Adapter whose Interface and ownership are explicit.

## Consequences

- `main` has one Auth vocabulary and one inward dependency direction.
- Removing the old source does not delete published artifacts or history.
- The reset established the stable Interface and portable assertion boundary.
  Concrete Providers may be added only as separate vNext crates with explicit
  ownership; ADR 0002 adds the first such Provider.
- CI rejects reintroduction of the removed workspace shape.
