import { defineConfig } from "vite";

// in dev, send /api calls to the python backend
export default defineConfig({
  server: {
    port: 5173,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
});
