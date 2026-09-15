import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Second app: the pay-cloud onboarding page. Built independently of the
// debugger (`vite.config.ts` → dist/) into dist-cloud/, which
// rust/crates/cloud embeds with include_dir.
export default defineConfig({
  root: "cloud",
  base: "/",
  publicDir: false,
  plugins: [react()],
  build: {
    outDir: "../dist-cloud",
    emptyOutDir: true,
  },
  server: {
    port: 5174,
    proxy: {
      "/api": "http://127.0.0.1:8402",
      "/v1": "http://127.0.0.1:8402",
    },
  },
});
