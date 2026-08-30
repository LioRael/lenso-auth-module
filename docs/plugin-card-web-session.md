# Auth Web Session Plugin card

## Outcome

A browser can start and complete one external OIDC login, receive the App's
normal opaque session as a hardened Cookie, and explicitly revoke that same
session on logout.

## Package and slot

- Package: `lenso-auth-web-session-plugin`
- Plugin id: `lenso.auth.web-session`
- Root slot: `auth`
- Instance key: one instance for the App's browser login routes

## Provides

- `lenso.http.endpoint@1`
  - `GET /auth/oidc/start`
  - `GET /auth/oidc/callback`
  - `POST /auth/logout`

## Requires

- `lenso.auth.federated@1` for authorization start and single-use callback
  completion
- `lenso.auth.credential-issuer@1` 1.1 for revocation by selected opaque
  credential
- a Web Ingress instance bound to this Endpoint, configured with the same
  session and CSRF Cookie names

The Federated provider and this Adapter must bind the same App session issuer.
Otherwise login could issue a credential that this Adapter cannot revoke.
The Federated provider's registered redirect URI must resolve to this
Adapter's fixed `/auth/oidc/callback` route on the selected Ingress origin.

## Owned behavior

The Plugin validates App-local return targets both before login and after
callback completion, redirects only to a secure authorization URL, and marks
auth responses `no-store`. On successful callback it emits:

- an opaque `__Host-` session Cookie with `Path=/`, `Secure`, `HttpOnly`, and
  `SameSite=Lax`; and
- a random `__Host-` double-submit CSRF Cookie with `Path=/`, `Secure`, and
  `SameSite=Lax`, intentionally without `HttpOnly` so browser code can copy it
  into the Ingress-configured CSRF request header.

Logout accepts only Endpoint credential evidence with `scheme=session`, calls
`revoke_credential` with the exact selected value, and expires both Cookies.
An absent session or an already-revoked session is cleared idempotently. An
invalid or unrecognized credential is also cleared, but returns `401`; the
Adapter never reports a revocation that the bound issuer could not confirm.

## Ingress boundary

Web Ingress owns Cookie parsing, rejection of Authorization/Cookie ambiguity,
double-submit CSRF enforcement on unsafe Cookie-authenticated methods, and
stripping Cookie and CSRF headers. The Endpoint receives only the selected
protocol-neutral `{scheme,value}` credential. No Cookie fields were added to an
Auth Capability.

## State and deletion boundary

This Plugin creates no database. OAuth Flow owns state/PKCE/nonce, the
Federated provider owns protocol validation, and Account Auth owns opaque
sessions and revocation. Removing this Plugin removes the browser routes and
Cookie responses but does not delete identities or sessions.
