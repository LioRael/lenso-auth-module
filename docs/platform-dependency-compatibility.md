# Auth platform dependency compatibility

Checked on 2026-08-11 against the published crates.io and npm registries. The Auth
workspace uses the following mutually compatible Lenso platform release set:

| Workspace dependency | Published crate | Declared minimum | Locked version |
| --- | --- | --- | --- |
| `contracts` | [`lenso-contracts`](https://crates.io/crates/lenso-contracts/0.4.0) | `0.4.0` | `0.4.0` |
| `platform-core` | [`lenso-platform-core`](https://crates.io/crates/lenso-platform-core/0.1.23) | `0.1.23` | `0.1.23` |
| `platform-http` | [`lenso-platform-http`](https://crates.io/crates/lenso-platform-http/0.1.22) | `0.1.22` | `0.1.22` |
| `platform-module` | [`lenso-platform-module`](https://crates.io/crates/lenso-platform-module/0.1.23) | `0.1.23` | `0.1.23` |
| `platform-runtime` | [`lenso-platform-runtime`](https://crates.io/crates/lenso-platform-runtime/0.1.20) | `0.1.20` | `0.1.20` |
| `platform-testing` | [`lenso-platform-testing`](https://crates.io/crates/lenso-platform-testing/0.1.19) | `0.1.19` | `0.1.19` |

The Console artifacts use the current published frontend contracts:

| Dependency | Declared version | Locked version |
| --- | --- | --- |
| `@lenso/console-module-api` | `^1.0.0` | `1.0.0` |
| `@lenso/console-ui` | `^1.0.0` | `1.0.0` |
| `react` / `react-dom` | `^19.2.8` | `19.2.8` |

The module manifests target Console Host API `^2.1.0` and Console UI protocol
`^2.0.0`. The package manager's minimum-release-age policy remains enabled for
new dependency releases.

Compatibility is verified by the locked workspace all-target check and test
suite, formatting check, and package/publish dry runs for each Auth crate.
