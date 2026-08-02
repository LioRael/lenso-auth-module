import { resolve } from "node:path";

import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: { emptyOutDir: true },
  plugins: [tailwindcss()],
  root: resolve(import.meta.dirname),
});
