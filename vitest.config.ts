import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    /**
     * P3-1: `src/tests/experimental/**` is the LoRA/Axolotl training-pipeline
     * test suite. Excluded from the default run because (a) the modules
     * require a 24GB+ GPU to actually run end-to-end, (b) the production
     * orchestrator never instantiates them, and (c) keeping them in the
     * default suite would slow CI / dev iteration without proving any
     * production capability.
     *
     * To run the experimental suite explicitly:
     *   npx vitest run src/tests/experimental/
     *
     * The reward_system + feedback_loop modules at the top level of
     * src/core/training/ are production-connected — their tests stay
     * in the default run.
     */
    exclude: [
      'node_modules',
      'src-tauri',
      // Drop the experimental exclude when RUN_EXPERIMENTAL=1 so opt-in
      // runs of `RUN_EXPERIMENTAL=1 npx vitest run src/tests/experimental/`
      // can find and execute those files.
      ...(process.env.RUN_EXPERIMENTAL === '1' ? [] : ['src/tests/experimental/**']),
    ],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/**/*.{test,spec}.{ts,tsx}',
        'src/main.tsx',
        'src/vite-env.d.ts',
        // Experimental training pipeline excluded from coverage too —
        // it's not in the production path.
        'src/core/training/experimental/**',
        'src/tests/experimental/**',
      ],
    },
    // Shorter timeout for unit tests, longer for integration
    testTimeout: 10000,
    hookTimeout: 10000,
  },
});
