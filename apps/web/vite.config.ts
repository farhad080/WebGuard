/// <reference types="vitest" />
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv } from 'vite';

// The repo keeps one .env at its root (shared with the API); read it from there.
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, repoRoot, '');
  // Where the dev server forwards /api. The SPA itself calls VITE_API_BASE_URL (default: same
  // origin), so in development requests go through this proxy and need no CORS.
  const apiTarget = env.VITE_API_PROXY_TARGET || `http://localhost:${env.PORT || 3000}`;

  return {
    envDir: repoRoot,
    plugins: [react()],
    server: {
      port: 5173,
      strictPort: true,
      proxy: { '/api': { target: apiTarget, changeOrigin: false } },
    },
    preview: {
      port: 4173,
      proxy: { '/api': { target: apiTarget, changeOrigin: false } },
    },
    build: {
      sourcemap: true,
      chunkSizeWarningLimit: 4096,
    },
    test: {
      environment: 'jsdom',
      setupFiles: ['./src/test/setup.ts'],
      include: ['src/**/*.test.{ts,tsx}'],
      css: false,
      restoreMocks: true,
    },
  };
});
