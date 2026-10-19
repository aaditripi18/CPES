import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The API runs on 8790 (dashboard/run_server.py); the dev server proxies /api to it.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8790" } },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
});
