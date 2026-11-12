import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Some suites scan several fixture projects end to end.
    testTimeout: 30_000,
  },
});
