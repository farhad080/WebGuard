/// <reference types="vitest" />
import { Server as HttpServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, type Plugin } from 'vite';

// The repo keeps one .env at its root (shared with the API); read it from there.
const repoRoot = fileURLToPath(new URL('../..', import.meta.url));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, repoRoot, '');
  // Where the dev server forwards /api. The SPA itself calls VITE_API_BASE_URL (default: same
  // origin), so in development requests go through this proxy and need no CORS.
  // The proxy streams request bodies with no body-size limit, so large ZIP uploads
  // (MAX_UPLOAD_MB on the API) pass through unchanged. The dev/preview server itself is a Node
  // HTTP server that drops requests taking over 5 min to arrive: raise that to the API's
  // UPLOAD_TIMEOUT_MS so a slow upload is not cut off before it reaches the API.
  const uploadTimeoutMs = Number(env.UPLOAD_TIMEOUT_MS) || 600_000;
  // Plain HTTP in dev/preview (no HTTPS/HTTP2 configured), so this is an http.Server.
  const raiseTimeout = (httpServer: unknown) => {
    if (httpServer instanceof HttpServer) httpServer.requestTimeout = uploadTimeoutMs;
  };
  const uploadTimeout: Plugin = {
    name: 'webguard-upload-timeout',
    configureServer(server) {
      raiseTimeout(server.httpServer);
    },
    configurePreviewServer(server) {
      raiseTimeout(server.httpServer);
    },
  };
  const apiTarget = env.VITE_API_PROXY_TARGET || `http://localhost:${env.PORT || 3000}`;

  return {
    envDir: repoRoot,
    plugins: [react(), uploadTimeout],
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
