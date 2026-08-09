import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const pairs = [
  ["crates/auth/console-module.json", "packages/auth-console/console-module.json"],
  [
    "crates/auth-device/console-module.json",
    "packages/auth-device-console/console-module.json",
  ],
  [
    "crates/auth-oauth/console-module.json",
    "packages/auth-oauth-console/console-module.json",
  ],
  [
    "crates/auth-github/console-module.json",
    "packages/auth-github-console/console-module.json",
  ],
  [
    "crates/auth-google/console-module.json",
    "packages/auth-google-console/console-module.json",
  ],
  [
    "crates/auth-oidc/console-module.json",
    "packages/auth-oidc-console/console-module.json",
  ],
];

for (const [rustPath, packagePath] of pairs) {
  const rustManifest = JSON.parse(
    await readFile(resolve(root, rustPath), "utf8")
  );
  const packageManifest = JSON.parse(
    await readFile(resolve(root, packagePath), "utf8")
  );
  if (JSON.stringify(rustManifest) !== JSON.stringify(packageManifest)) {
    throw new Error(`Console manifest drift: ${rustPath} != ${packagePath}`);
  }
}

console.log(`Verified ${pairs.length} Rust/package Console manifests`);
