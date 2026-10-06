import { fileURLToPath, URL } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

const API_TARGET = process.env.VIBESEC_API_URL ?? 'http://localhost:4000';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: {
    port: 5180,
    strictPort: true,
    // Same-origin in dev: the browser talks to Vite, Vite forwards /api (incl. the SSE stream) to Fastify.
    proxy: { '/api': { target: API_TARGET, changeOrigin: true } },
  },
  build: {
    rolldownOptions: {
      output: {
        // Long-lived vendor chunks so app deploys don't bust the framework cache. Shiki stays lazy:
        // lib/highlighter.ts imports each `@shikijs/langs`/`@shikijs/themes` grammar by name instead of
        // shiki's generic bundled-name lookup, so only the ~20 languages we actually use ship at all
        // (not shiki's full ~240-grammar catalogue).
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\/](react|react-dom|react-router|scheduler)[\/]/ },
            { name: 'ui', test: /node_modules[\/](radix-ui|@radix-ui|cmdk|sonner|lucide-react|@floating-ui)[\/]/ },
            { name: 'data', test: /node_modules[\/](@tanstack|zod)[\/]/ },
          ],
        },
      },
    },
    // The one chunk still over the default 500 kB: @shikijs/langs/ruby statically bundles several
    // grammars it can highlight embedded in Ruby (html, haml, sql, graphql, css, cpp, c, js, sh, lua,
    // yaml) — that's inherent to the packaged grammar, not something this app's splitting controls,
    // and it's lazy (fetched only when a .rb file is actually opened in the code viewer).
    chunkSizeWarningLimit: 1_000,
  },
  preview: { port: 4173, proxy: { '/api': { target: API_TARGET, changeOrigin: true } } },
});
