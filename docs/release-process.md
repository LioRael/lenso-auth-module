# Release Process

This repository independently releases its Rust crates. The Console packages
are private build inputs for module artifacts and are not npm publication
targets. Releases are not coordinated by a repository-wide release plan.

## Rust crates

Release-plz runs on pushes to `main`:

1. `release-pr` opens or updates a release pull request for changed public
   workspace crates.
2. `release` publishes the versions from a merged release pull request through
   crates.io Trusted Publishing and creates a package tag and GitHub Release.

The tag convention is `<crate>@<version>`. The crates.io registry is the source
of truth for versions already published. Existing public versions, tags, and
changelogs are not rewritten. No long-lived `CARGO_REGISTRY_TOKEN` is used by
the workflow.

Before enabling the first live publish, configure a crates.io Trusted Publisher
for each public crate in this repository and verify the repository and workflow
claims match `.github/workflows/release-plz.yml`.

The release job uses the repository `RELEASE_PLZ_TOKEN` secret because this
repository's immutable tag ruleset protects package tags from the default
GitHub Actions token. The token is used only for GitHub tag and release
metadata; crate publication still uses crates.io Trusted Publishing through
the workflow's OIDC identity.

## Local checks

Run the Rust checks and build the private Console artifacts when their source
changes:

```sh
cargo fmt --all --check
cargo test --locked --workspace
cargo package --locked -p lenso-module-auth --allow-dirty
cargo publish --dry-run --locked -p lenso-module-auth --allow-dirty
pnpm install --frozen-lockfile
pnpm check
```

Use the corresponding `cargo package` and `cargo publish --dry-run` commands
for every changed crate. Use `pnpm check` to validate the private Console
artifact inputs; do not publish those packages to npm.

Cross-repository compatibility is proven by SemVer requirements, committed
contracts, consumer dependency updates, and focused integration checks. A
tested combination is evidence, not a shared release object. Do not restore a
central publisher, shadow registry, nonce, or global release channel to repair a
failed publication.
