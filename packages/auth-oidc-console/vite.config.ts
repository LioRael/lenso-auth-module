import { resolve } from "node:path";

import stylex from "@stylexjs/unplugin/vite";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    emptyOutDir: true,
    lib: {
      cssFileName: "stylex",
      entry: resolve(import.meta.dirname, "src/index.tsx"),
      fileName: "index.js",
      formats: ["es"],
    },
    rolldownOptions: {
      output: {
        assetFileNames: "assets/[name][extname]",
        chunkFileNames: "chunks/[name]-[hash].js",
        entryFileNames: "index.js",
      },
    },
  },
  plugins: [stylex({ devMode: "off", useCSSLayers: true })],
  root: resolve(import.meta.dirname),
});
