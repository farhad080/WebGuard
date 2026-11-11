import { fileURLToPath } from 'node:url';
import { config as loadEnv } from 'dotenv';
import { defineConfig } from 'vitest/config';

loadEnv({ path: fileURLToPath(new URL('../../.env', import.meta.url)), quiet: true });

const testDatabaseUrl =
  process.env.TEST_DATABASE_URL ?? 'postgres://webguard:webguard@localhost:5432/webguard_test';

export default defineConfig({
  test: {
    env: {
      DATABASE_URL: testDatabaseUrl,
      JWT_SECRET: process.env.JWT_SECRET ?? 'test-only-jwt-secret',
    },
    globalSetup: ['./test/global-setup.ts'],
    // Tests share one database; run files sequentially.
    fileParallelism: false,
  },
});
