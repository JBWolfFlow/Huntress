import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/tests/integration/live_pipeline.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 30_000,
    // These tests require external services — run sequentially
    pool: 'forks',
    poolOptions: {
      forks: { singleFork: true },
    },
  },
});
