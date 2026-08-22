#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-auth-sdk\nlenso-capability-auth'
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
  'lenso-(contracts|module-auth|platform-(core|http|module|runtime|testing))' \
  Cargo.toml crates --glob 'Cargo.toml'; then
  printf 'legacy v0.3 dependency returned\n' >&2
  exit 1
fi

printf 'repository boundary is vNext-only\n'
