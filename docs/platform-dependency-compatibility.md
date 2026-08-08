# Auth platform dependency compatibility

Checked on 2026-08-09 against the published crates.io registry. The Auth
workspace uses the following mutually compatible Lenso platform release set:

| Workspace dependency | Published crate | Declared minimum | Locked version |
| --- | --- | --- | --- |
| `platform-core` | [`lenso-platform-core`](https://crates.io/crates/lenso-platform-core/0.1.22) | `0.1.22` | `0.1.22` |
| `platform-http` | [`lenso-platform-http`](https://crates.io/crates/lenso-platform-http/0.1.21) | `0.1.21` | `0.1.21` |
| `platform-module` | [`lenso-platform-module`](https://crates.io/crates/lenso-platform-module/0.1.22) | `0.1.22` | `0.1.22` |
| `platform-runtime` | [`lenso-platform-runtime`](https://crates.io/crates/lenso-platform-runtime/0.1.19) | `0.1.19` | `0.1.19` |
| `platform-testing` | [`lenso-platform-testing`](https://crates.io/crates/lenso-platform-testing/0.1.18) | `0.1.18` | `0.1.18` |

The updated platform crates require `lenso-contracts` `0.3.21` transitively.
No other lockfile dependency changed.

Compatibility is verified by the locked workspace all-target check and test
suite, formatting check, and package/publish dry runs for each Auth crate.
