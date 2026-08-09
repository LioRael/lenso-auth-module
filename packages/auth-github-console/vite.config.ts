import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    emptyOutDir: true,
    lib: {
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
  plugins: [tailwindcss()],
  root: resolve(import.meta.dirname),
});
