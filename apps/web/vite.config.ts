import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const API_TARGET = process.env.VIBESEC_API_URL ?? 'http://localhost:4000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5173,
    strictPort: true,
    // Same-origin in dev: the browser talks to Vite, Vite forwards /api (incl. the SSE stream) to Fastify.
    proxy: { '/api': { target: API_TARGET, changeOrigin: true } },
  },
  build: {
    rolldownOptions: {
      output: {
        // Long-lived vendor chunks so app deploys don't bust the framework cache. Shiki stays lazy.
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\/](react|react-dom|react-router|scheduler)[\/]/ },
            { name: 'ui', test: /node_modules[\/](radix-ui|@radix-ui|cmdk|sonner|lucide-react|@floating-ui)[\/]/ },
            { name: 'data', test: /node_modules[\/](@tanstack|zod)[\/]/ },
          ],
        },
      },
    },
  },
  preview: { port: 4173, proxy: { '/api': { target: API_TARGET, changeOrigin: true } } },
});
