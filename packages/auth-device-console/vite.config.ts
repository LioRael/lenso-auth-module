import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const hostImports = {
  "@lenso/runtime-console-api":
    "/console/extensions/host/runtime-console-api.js",
  react: "/console/extensions/host/react.js",
  "react/jsx-runtime": "/console/extensions/host/react-jsx-runtime.js",
};
const require = createRequire(import.meta.url);
const siblingRuntimeConsoleApiTheme = resolve(
  import.meta.dirname,
  "../../../lenso-runtime-console/packages/console-package-api/theme.css"
);
const fallbackRuntimeConsoleApiTheme = resolve(
  import.meta.dirname,
  "../auth-console/src/runtime-console-theme.css"
);
const runtimeConsoleApiTheme =
  optionalResolve("@lenso/runtime-console-api/theme.css") ??
  (existsSync(siblingRuntimeConsoleApiTheme)
    ? siblingRuntimeConsoleApiTheme
    : fallbackRuntimeConsoleApiTheme);

function optionalResolve(specifier: string) {
  try {
    return require.resolve(specifier);
  } catch {
    return null;
  }
}

export default defineConfig({
  build: {
    emptyOutDir: true,
    lib: {
      cssFileName: "auth-device-console",
      entry: resolve(import.meta.dirname, "src/index.tsx"),
      fileName: () => "auth-device-console.js",
      formats: ["es"],
    },
    rollupOptions: {
      external: Object.keys(hostImports),
      output: {
        paths: hostImports,
      },
    },
  },
  resolve: {
    alias: {
      "@lenso/runtime-console-api/theme.css": runtimeConsoleApiTheme,
    },
  },
  plugins: [tailwindcss()],
});
