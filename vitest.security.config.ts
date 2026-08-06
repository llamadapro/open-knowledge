import { defineConfig } from 'vitest/config';
import { okVitestBase } from './test-support/vitest.base';

export default defineConfig({
  ...okVitestBase,
  test: {
    ...okVitestBase.test,
    include: [
      'packages/core/src/security/**/*.test.ts',
      'packages/server/src/http/api-pipeline.test.ts',
      'packages/server/src/security/**/*.test.ts',
    ],
    coverage: {
      provider: 'v8',
      include: [
        'packages/core/src/security/**/*.ts',
        'packages/server/src/security/**/*.ts',
        'packages/server/src/http/security-context.ts',
      ],
      exclude: ['**/*.test.ts'],
      reporter: ['text', 'json-summary'],
      reportsDirectory: 'coverage/security',
      thresholds: {
        branches: 100,
        functions: 100,
        lines: 100,
        statements: 100,
      },
    },
  },
});
