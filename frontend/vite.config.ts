import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The dashboard talks to the API through a same-origin "/api" prefix, so no CORS is needed.
// In development Vite forwards it to the FastAPI server (uvicorn ... --port 8000).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.AEGIS_API ?? "http://localhost:8000",
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  test: { environment: "node" },
});
