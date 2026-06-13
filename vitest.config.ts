/**
 * Vitest Configuration
 * 
 * Configuration for running tests with TypeScript support.
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    testTimeout: 10000,
    hookTimeout: 10000,
    teardownTimeout: 5000,
    // Mock process.env for testing
    setupFiles: ['./tests/setup.ts'],
    // Env applied BEFORE any test module is imported. SESSION_SECRET is required
    // at auth-service.ts module-load (else it process.exit(1)s); the setup.ts
    // beforeAll runs too late for hoisted imports. Additive: same value setup.ts uses.
    env: {
      SESSION_SECRET: 'test-session-secret-for-testing-minimum-32-characters',
      NODE_ENV: 'test',
    },
  },
  esbuild: {
    target: 'node18',
  },
});