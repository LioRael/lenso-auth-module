# Release

## npm trusted publishing

Runtime Console npm packages publish from `.github/workflows/release.yml` with
npm trusted publishing. The workflow uses GitHub Actions OIDC through
`id-token: write`; it should not need a long-lived npm publish token after each
package exists on npm and has a trusted publisher configured.

One-time npm package setup:

```sh
npm install -g npm@latest
npm login
npm trust github @lenso/auth-console \
  --repo LioRael/lenso-auth-module \
  --file release.yml \
  --env release \
  --allow-publish
```

Repeat the same `npm trust github` command for every published console package:

```sh
npm trust github @lenso/auth-device-console \
  --repo LioRael/lenso-auth-module \
  --file release.yml \
  --env release \
  --allow-publish

npm trust github @lenso/auth-provider-console \
  --repo LioRael/lenso-auth-module \
  --file release.yml \
  --env release \
  --allow-publish
```

npm requires a package to exist before trusted publishing can be configured for
it. For a brand-new package name, bootstrap the first public version once from CI
with an npm token that can create packages under the `@lenso` scope, then add the
trusted publisher and use the normal Release workflow for subsequent versions.

Normal npm-only release:

```sh
gh workflow run Release --ref main \
  -f publish_auth_crate=false \
  -f publish_password_crate=false \
  -f publish_npm=true
```
