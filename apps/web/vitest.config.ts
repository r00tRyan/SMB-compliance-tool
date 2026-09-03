import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      // `server-only` throws outside a React Server Components bundler; in tests
      // we exercise these modules directly, so swap it for its no-op build.
      'server-only': resolve(__dirname, 'node_modules/server-only/empty.js'),
    },
  },
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    hookTimeout: 30_000,
  },
});
