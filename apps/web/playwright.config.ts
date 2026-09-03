import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  fullyParallel: false,
  retries: 0,
  use: {
    baseURL: process.env.APP_URL ?? 'http://localhost:3000',
    trace: 'on-first-retry',
  },
  webServer: process.env.PW_NO_SERVER
    ? undefined
    : {
        command: 'pnpm --filter @smb/web start',
        url: process.env.APP_URL ?? 'http://localhost:3000',
        reuseExistingServer: true,
        timeout: 120_000,
      },
});
