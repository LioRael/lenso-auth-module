import { mkdtemp, mkdir, readFile, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const packageRoot = join(root, "packages/auth-console");
const target = join(root, "crates/auth/artifacts/auth-console.tgz");
const contractSource = join(packageRoot, "src/auth-business-api.v1.json");
const contractTarget = join(root, "crates/auth/artifacts/auth-business-api.v1.json");
const check = process.argv.includes("--check");
const temporary = await mkdtemp(join(tmpdir(), "lenso-auth-console-"));

try {
  run("pnpm", ["--dir", packageRoot, "build"]);
  const packed = run("npm", [
    "pack",
    packageRoot,
    "--json",
    "--pack-destination",
    temporary,
  ]);
  const [{ filename }] = JSON.parse(packed);
  const generated = join(temporary, filename);
  if (check) {
    const [expected, actual, expectedContract, actualContract] = await Promise.all([
      readFile(target),
      readFile(generated),
      readFile(contractTarget),
      readFile(contractSource),
    ]);
    if (!expected.equals(actual) || !expectedContract.equals(actualContract)) {
      throw new Error(
        "Auth Console artifact is stale; run `pnpm build:console-artifact`",
      );
    }
    process.stdout.write("Auth Console artifact is current.\n");
  } else {
    await mkdir(resolve(target, ".."), { recursive: true });
    await Promise.all([
      copyFile(generated, target),
      copyFile(contractSource, contractTarget),
    ]);
    process.stdout.write(`Wrote ${target} and ${contractTarget}\n`);
  }
} finally {
  await rm(temporary, { force: true, recursive: true });
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["inherit", "pipe", "inherit"],
  });
  if (result.status !== 0) {
    throw new Error(`${command} exited with ${result.status}`);
  }
  return result.stdout;
}
