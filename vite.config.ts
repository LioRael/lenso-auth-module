import { resolve } from "node:path";

import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@lenso/runtime-console-api": resolve(
        import.meta.dirname,
        "../lenso-runtime-console/packages/console-package-api/src/index.ts"
      ),
    },
  },
});
