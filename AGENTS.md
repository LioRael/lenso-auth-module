# Agent instructions

The default `main` branch is Lenso vNext-only. The `v0.3` branch and existing
package tags retain the previous implementation and release history.

Before architecture or implementation changes, read `CONTEXT.md`, the local
ADRs under `docs/adr/`, and the normative Lenso ADRs linked from them. Before
changing or executing a release, read `docs/release-process.md`.

Create task worktrees from the latest `origin/main` with `wt switch --create`.
Preserve unrelated dirty work and run Cargo through
`/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo` when
available.

Keep the Auth Interface protocol-neutral. Ingress Adapters own credential
extraction; Auth owns authentication and assertion issuance; target Modules own
authorization. Do not add HTTP, database, Redis, Console, v0.3 platform, or
product release concerns to the portable Auth crates.

The Capability descriptor is authoritative. Regenerate Rust and TypeScript
bindings through `lenso-contract-codegen`; never hand-edit generated files.

Use a concise imperative Conventional Commit subject under 72 characters.
Validate with the repository boundary check, locked format/check/test gates,
and package dry-runs for changed public crates.
