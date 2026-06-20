import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

const hostImports = {
  "@lenso/runtime-console-api":
    "/console/extensions/host/runtime-console-api.js",
  react: "/console/extensions/host/react.js",
  "react/jsx-runtime": "/console/extensions/host/react-jsx-runtime.js",
};

export default defineConfig({
  build: {
    emptyOutDir: true,
    lib: {
      cssFileName: "auth-console",
      entry: resolve(import.meta.dirname, "src/index.tsx"),
      fileName: () => "auth-console.js",
      formats: ["es"],
    },
    rollupOptions: {
      external: Object.keys(hostImports),
      output: {
        paths: hostImports,
      },
    },
  },
  plugins: [tailwindcss()],
});
