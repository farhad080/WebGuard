import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadEnv } from 'dotenv';
import { defineConfig } from 'vitest/config';

loadEnv({ path: fileURLToPath(new URL('../../.env', import.meta.url)), quiet: true });

const testDatabaseUrl =
  process.env.TEST_DATABASE_URL ?? 'postgres://webguard:webguard@localhost:5432/webguard_test';

export default defineConfig({
  resolve: {
    // Test against workspace sources, not possibly-stale dist builds.
    alias: {
      '@webguard/analysis': fileURLToPath(
        new URL('../../packages/analysis/src/index.ts', import.meta.url),
      ),
    },
  },
  test: {
    env: {
      DATABASE_URL: testDatabaseUrl,
      JWT_SECRET: process.env.JWT_SECRET ?? 'test-only-jwt-secret',
      REDIS_URL: process.env.REDIS_URL ?? 'redis://localhost:6379',
      // Isolated from the dev queue and dev storage.
      SCAN_QUEUE_NAME: 'webguard-test-scans',
      STORAGE_DIR: path.join(os.tmpdir(), 'webguard-test-storage'),
    },
    globalSetup: ['./test/global-setup.ts'],
    // Tests share one database and one queue; run files sequentially.
    fileParallelism: false,
    testTimeout: 30_000,
  },
});
