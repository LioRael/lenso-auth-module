# Release process

The default branch contains two public vNext Rust crates:

- `lenso-capability-auth`
- `lenso-auth-sdk`

Automated publication is intentionally disabled while this extracted
repository establishes a new release baseline. The crates were first published
from a different repository history, which release-plz cannot safely compare
with this repository's pre-extraction commits. The parked workflow is
manual-only and reports this state without invoking release-plz. Pushes to
`main` do not run a publication workflow.

Re-enable publication in a dedicated release-bootstrap change only after:

1. creating an explicit post-extraction version baseline for both crates;
2. proving release-plz no longer traverses the incompatible imported history;
3. configuring a crates.io Trusted Publisher for both crates with repository
   `LioRael/lenso-auth-module` and workflow `.github/workflows/release-plz.yml`;
   and
4. validating the workflow in dry-run mode before granting live publication.

Do not use a long-lived Cargo registry token or infer publication authority
from GitHub write access. Existing versions are immutable and registry state is
authoritative.

The `v0.3` branch retains the old release-line source. Its packages, tags, and
release procedure are not part of `main` and must not be recreated here.

## Local checks

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo package --locked -p lenso-capability-auth --allow-dirty
cargo package --locked -p lenso-auth-sdk --allow-dirty
./scripts/check-repository-boundary.sh
```

Generated bindings must be fresh before packaging. Use the owning
`lenso-contract-codegen` generator rather than editing generated output.
