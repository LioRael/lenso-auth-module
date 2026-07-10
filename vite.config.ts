import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { defineConfig } from "vitest/config";

const runtimeConsoleApiSource = resolve(
  import.meta.dirname,
  "../lenso-runtime-console/packages/console-package-api/src/index.ts"
);

export default defineConfig({
  resolve: {
    alias: existsSync(runtimeConsoleApiSource)
      ? { "@lenso/runtime-console-api": runtimeConsoleApiSource }
      : {},
  },
});
