# Release process

The default branch contains five public vNext Rust crates:

- `lenso-capability-auth`
- `lenso-auth-sdk`
- `lenso-capability-credential-issuer`
- `lenso-capability-identity-directory`
- `lenso-capability-password-auth`

All other workspace members are private implementation crates and must keep
`publish = false`.

Publication is manual-only. The `Release-plz` workflow has a read-only dry-run
mode and a separately gated live mode. It uses the explicit versions in the
post-extraction workspace as the release baseline, so release-plz does not
derive versions by traversing the imported pre-extraction history.

## Trusted publishing and first releases

Configure a crates.io Trusted Publisher for every already-published crate with:

- repository: `LioRael/lenso-auth-module`
- workflow: `.github/workflows/release-plz.yml`
- environment: unset

Trusted Publishing cannot allocate a new crate name. Before invoking the live
workflow, publish the first version of each new crate from a reviewed, clean
`main` checkout with a temporary crates.io token restricted to new-package
publication, then revoke that token immediately:

- `lenso-capability-credential-issuer` version `0.1.0`
- `lenso-capability-identity-directory` version `0.1.0`
- `lenso-capability-password-auth` version `0.1.0`

Do not store that bootstrap token in Cargo credentials, repository secrets,
workflow logs, or shell history. After the first release, configure the same
Trusted Publisher for each new crate. Do not run the live workflow until all
five Trusted Publishers match the repository and workflow above.

With the temporary token supplied by a credential helper, the bootstrap
commands are:

```sh
cargo publish --locked -p lenso-capability-credential-issuer
cargo publish --locked -p lenso-capability-identity-directory
cargo publish --locked -p lenso-capability-password-auth
```

After crates.io confirms each upload, create its matching GitHub release from
the exact reviewed `main` commit. The release tag format is
`<package>@<version>`, matching `release-plz.toml`.

## Release gates

Run the workflow dry-run from `main` first:

```sh
gh workflow run release-plz.yml --ref main -f live=false
```

Inspect the completed run and confirm that it identifies only the intended
unpublished versions. Live publication requires both the `main` ref and the
literal confirmation value `publish`:

```sh
gh workflow run release-plz.yml --ref main -f live=true -f confirm=publish
```

The live job obtains a short-lived crates.io credential through GitHub OIDC.
It does not accept a Cargo registry token. Existing versions are immutable and
registry state is authoritative.

The `v0.3` branch retains the old release-line source. Its packages, tags, and
release procedure are not part of `main` and must not be recreated here.

## Local checks

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo package --locked -p lenso-capability-auth --allow-dirty
cargo package --locked -p lenso-auth-sdk --allow-dirty
cargo package --locked -p lenso-capability-credential-issuer --allow-dirty
cargo package --locked -p lenso-capability-identity-directory --allow-dirty
cargo package --locked -p lenso-capability-password-auth --allow-dirty
./scripts/check-repository-boundary.sh
```

Generated bindings must be fresh before packaging. Use the owning
`lenso-contract-codegen` generator rather than editing generated output.
