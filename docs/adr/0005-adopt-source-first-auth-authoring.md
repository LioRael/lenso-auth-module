# ADR 0005: Adopt source-first Auth authoring

- Status: accepted
- Date: 2026-08-25
- Upstream: Lenso ADR 0066

## Context

Auth Capabilities repeated one contract across hand-authored Descriptor and
Schema JSON plus generated Rust. Auth Modules repeated Cargo-owned package
identity in constants and hand-written `NativeModuleFactory` implementations.
Those surfaces can drift even when the runtime behavior remains correct.

## Decision

Each Auth Capability is authored as Rust value types and one
`#[lenso::capability]` trait. The build derives and checks committed Descriptor
and Schema snapshots, then checks the generated native Rust projection. Native
Capability repositories do not regain a generated TypeScript projection.

Each native Auth Module declares `[package.metadata.lenso].package-id` and one
`#[lenso::module]` entrypoint. The macro derives package identity, the linked
Factory, and registration. Existing state preparation, dependency resolution,
and explicit generated endpoints remain unchanged during this mechanical
migration; moving them to struct-level `Port<Client>` and `#[lenso::provides]`
is a later behavior-preserving refactor, not a compatibility requirement.

## Consequences

- Hand-written package identity constants and `NativeModuleFactory`
  implementations are removed from production Auth Modules.
- Descriptor and Schema files remain committed runtime and review authorities,
  but they are generated lockfiles rather than author inputs.
- Contract changes start in `src/contract.rs` and require an intentional
  snapshot update plus regenerated Rust projection.
- App Composition still selects and binds Module Instances; linked registration
  does not create ambient Auth discovery or fallback.
