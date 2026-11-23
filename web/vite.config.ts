/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Dos modos de compilación:
//  - normal: el panel se embebe en el binario de Go y habla con la API real (/api/v1).
//  - demo:   GitHub Pages; lee JSON estáticos de public/demo y no necesita servidor.
export default defineConfig(({ mode }) => ({
  plugins: [react()],
  base: mode === "demo" ? "./" : "/",
  // Los datos de la demo solo se copian en el modo demo: no inflan el binario.
  publicDir: mode === "demo" ? "demo-public" : "public",
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: mode === "demo" ? "dist" : "../backend/internal/adapters/httpapi/ui/dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
}));
