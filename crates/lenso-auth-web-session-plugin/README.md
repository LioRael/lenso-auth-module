# Lenso Auth Web Session Plugin

`lenso-auth-web-session-plugin` is the browser HTTP Adapter for one bound
Federated Auth provider. It exposes fixed start, callback, and logout routes,
sets the App's opaque credential as a secure host cookie, and delegates session
revocation to the bound Credential Issuer.

Routes:

- `GET /auth/oidc/start?return_to=/local/path`
- `GET /auth/oidc/callback?code=...&state=...`
- `POST /auth/logout`

Both Cookie names must use the `__Host-` prefix. The session Cookie is always
`Secure`, `HttpOnly`, `SameSite=Lax`, and `Path=/`. The Plugin also issues a
`Secure`, `SameSite=Lax` CSRF Cookie that is
intentionally readable by the browser client. Configure Web Ingress with the
same two Cookie names and a dedicated CSRF request header. Web Ingress enforces
double-submit CSRF before dispatching unsafe Cookie-authenticated methods and
strips Cookie and CSRF headers before the Endpoint runs.

This Plugin has no session database. Account Auth continues to own the opaque
session credential and its revocation state. An unrecognized logout credential
still clears the browser Cookies, but returns `401` instead of claiming that an
unconfirmed revocation succeeded.
