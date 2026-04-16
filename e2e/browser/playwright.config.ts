import { defineConfig, devices } from '@playwright/test';

/**
 * Browser E2E tests for the instant.dev onboarding flow.
 *
 * These tests hit the REAL k8s cluster — no mocks, no Vite dev server.
 * The API must be running at E2E_API_URL (default: http://localhost:30080).
 *
 * Setup:
 *   NODE_PORT=$(kubectl get svc instant-api -n instant -o jsonpath='{.spec.ports[0].nodePort}')
 *   E2E_API_URL=http://localhost:${NODE_PORT} npx playwright test
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false, // run sequentially — each test provisions real resources
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['html', { outputFolder: 'playwright-report' }], ['list']],
  use: {
    baseURL: process.env.E2E_API_URL ?? 'http://localhost:30080',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    // No JS console errors allowed.
    ignoreHTTPSErrors: false,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // No webServer — the k8s API is already running.
});
