import { defineConfig } from "vite";

// No framework plugin: JSX is compiled by Vite's built-in transformer (automatic runtime).
export default defineConfig({
  base: "/",
  oxc: { jsx: { runtime: "automatic" } },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    // No inline polyfill script: the UI's CSP allows only scripts from 'self'.
    modulePreload: { polyfill: false },
  },
});
