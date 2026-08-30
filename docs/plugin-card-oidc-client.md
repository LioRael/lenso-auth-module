# OIDC Client Plugin card

## Outcome

A human can authenticate with one configured external OpenID Connect provider,
map its stable subject to the App's canonical identity, and receive the App's
normal opaque session credential.

## Package and slot

- Package: `lenso-auth-oidc-client-plugin`
- Plugin id: `lenso.auth.oidc-client`
- Root slot: `auth`
- Instance key: one instance per external issuer/client registration

## Provides

- `lenso.auth.federated@1`: `start` and `complete`

## Requires

- `lenso.auth.oauth-flow@1` for single-use state, PKCE verifier, nonce, expiry,
  and safe local return target custody
- `lenso.http.client@1` for token and JWKS requests, with Host grants limited to
  the configured token and JWKS origins
- `lenso.auth.identity-directory@1` for external-subject mapping
- `lenso.auth.credential-issuer@1` for the App-owned opaque session
- `lenso.secrets@1` for the client secret

When composed with `lenso-auth-web-session-plugin`, the registered
`redirect_uri` must resolve to that Adapter's fixed
`/auth/oidc/callback` route on the selected Ingress origin.

## Owned behavior

The Plugin builds the authorization redirect, exchanges the code with PKCE,
loads the configured issuer's JWKS, and accepts only an RS256 ID token with a
unique configured `kid`, valid signature, exact issuer, client audience, valid
expiry and issued-at time, matching single-use nonce, and valid `azp` when
required by a multi-audience token.

It owns the active client secret value only for its generation. It does not own
canonical identities, sessions, an HTTP server, a browser cookie, or the
existing Lenso OIDC issuer.

## Deletion boundary

Removing the instance removes that external login path. OAuth flow rows expire
independently; identity bindings and App sessions remain owned by their bound
providers and are not deleted or invalidated implicitly.

## Browser Adapter

`lenso-auth-web-session-plugin` is the optional HTTP Endpoint Adapter for this
flow. It exposes start/callback/logout, revalidates the local return target at
the response boundary, sets the secure opaque session and CSRF Cookies, and
revokes the selected credential on logout. These wire behaviors remain outside
this protocol client.
