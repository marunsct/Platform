/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The build lands in internal/portal/dist, which maturad embeds and serves at /portal/.
// In development (npm run dev) the API and /portal/config.json come from a maturad on :8080.
const maturad = process.env.MATURAD_URL ?? "http://localhost:8080";

export default defineConfig({
  base: "/portal/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../../internal/portal/dist",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 600,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": maturad,
      "/admin/v1": maturad,
      "/portal/config.json": maturad,
    },
  },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
