import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const output = execFileSync(
  "cargo",
  ["run", "--quiet", "-p", "lenso-module-auth", "--example", "console_module_manifest"],
  { cwd: root, encoding: "utf8" }
);

await writeFile(
  resolve(root, "packages/auth-console/console-module.json"),
  output,
  "utf8"
);
