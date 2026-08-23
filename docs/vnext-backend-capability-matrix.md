# vNext Auth backend capability matrix

This matrix uses the crates on `origin/v0.3` as the restoration baseline. HTTP
route extraction/response mapping, Console manifests/artifacts, and frontend
packages are intentionally excluded. Those are Adapter or UI responsibilities.

| v0.3 owner | Restored behavior | vNext owner | Status |
| --- | --- | --- | --- |
| `auth` | canonical users, identities, sessions, disable/enable, session revocation, administrative reads | Account Module plus Account Admin Capability | complete |
| `auth-anonymous` | anonymous subject and session creation, stable device-scoped identity | Anonymous Auth Module | complete |
| `auth-device` | observe devices and client metadata, trust/primary facts, administrative reads | Device Auth Module | complete |
| `auth-password` | register, login, Argon2id hashes, provider-scoped failure limiting | Password Auth Module | complete |
| `auth-oauth` | expiring single-use OAuth state, encrypted PKCE verifier, safe return target | OAuth Flow Module | complete |
| `auth-github` | authorization start, code exchange, GitHub identity mapping and session | provider-keyed Federated Auth Module instance | complete |
| `auth-google` | authorization start, code exchange, verified Google identity mapping and session | provider-keyed Federated Auth Module instance | complete |
| `auth-oidc` | metadata/JWKS, authorization-code issuance, PKCE token exchange, ID/access tokens | OIDC Provider Module | complete |
| `auth-phone` | normalized phone identities, OTP start/verify/resend limits, phone password set/login | Phone Auth Module plus bound SMS Delivery Capability | complete |

The existing API Token Module is additional vNext behavior and remains a peer
credential provider. The Auth Router provides explicit scheme-to-provider
instance selection when a caller accepts more than one `lenso.auth@1`
provider; it never tries another provider after a rejection.

“Complete” here means the protocol-neutral backend capability, native Module,
private-state ownership, file-backed PostgreSQL migration plan,
lifecycle/operator seam, and App Composition behavior exist and pass workspace
tests and lints. PostgreSQL acceptance tests are environment-gated by
`LENSO_POSTGRES_TEST_URL`. HTTP routes, browser/cookie policy, Web UI, and
Console artifacts remain intentionally out of scope.
