#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-auth-account-plugin\nlenso-auth-anonymous-plugin\nlenso-auth-api-token-plugin\nlenso-auth-device-plugin\nlenso-auth-federated-plugin\nlenso-auth-oauth-flow-plugin\nlenso-auth-oidc-client-plugin\nlenso-auth-oidc-plugin\nlenso-auth-password-plugin\nlenso-auth-phone-plugin\nlenso-auth-router-plugin\nlenso-auth-sdk\nlenso-auth-web-session-plugin\nlenso-capability-account-admin\nlenso-capability-anonymous-auth\nlenso-capability-auth\nlenso-capability-credential-issuer\nlenso-capability-device-auth\nlenso-capability-federated-auth\nlenso-capability-identity-directory\nlenso-capability-oauth-flow\nlenso-capability-oidc-provider\nlenso-capability-password-auth\nlenso-capability-phone-auth\nlenso-capability-sms-delivery'
actual_crates="$({
  find crates -mindepth 1 -maxdepth 1 -type d -exec basename {} \;
} | LC_ALL=C sort)"

if [[ "$actual_crates" != "$expected_crates" ]]; then
  printf 'unexpected crate ownership:\n%s\n' "$actual_crates" >&2
  exit 1
fi

for removed_path in package.json packages pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json; do
  if [[ -e "$removed_path" ]]; then
    printf 'legacy frontend path returned: %s\n' "$removed_path" >&2
    exit 1
  fi
done

if rg -n \
  '^[[:space:]]*lenso-(contracts|module-auth|platform-(core|http|module|runtime|testing))[[:space:]]*=' \
  Cargo.toml crates --glob 'Cargo.toml'; then
  printf 'legacy v0.3 dependency returned\n' >&2
  exit 1
fi

if rg -n \
  'sqlx|postgres|lenso-postgres-kit|lenso-native-adapter|lenso-capability-secrets' \
  crates/lenso-auth-sdk/Cargo.toml crates/lenso-capability-auth/Cargo.toml; then
  printf 'portable Auth crate gained a concrete Adapter dependency\n' >&2
  exit 1
fi

printf 'repository boundary is vNext-only\n'
