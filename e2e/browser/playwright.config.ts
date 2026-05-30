import { defineConfig, devices } from '@playwright/test';

/**
 * Browser E2E tests for the instanode.dev onboarding flow.
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
    {
      // Layer-2 docker-compose auth-contract gate
      // (tests/auth-contract-local.spec.ts) — needs Chromium's Local /
      // Private Network Access checks disabled because both the document
      // origin (http://localhost:5173, stubbed) and the api (http://localhost
      // :8080) live in the loopback address space, and Chromium blocks
      // even loopback→loopback fetches as a CORS pre-PNA "permission denied"
      // when there is no Access-Control-Allow-Private-Network header.
      // PROD does not hit this case (instanode.dev → api.instanode.dev are
      // both public addresses), so the PNA disable is strictly a localhost
      // shim — it does NOT weaken the contract under test, which is the
      // CORS allow-origin + allow-credentials response from the api.
      name: 'chromium-compose-pna',
      testMatch: /auth-contract-local\.spec\.ts/,
      use: {
        ...devices['Desktop Chrome'],
        launchOptions: {
          args: [
            // Disable the full family of PNA / LNA blocking features. Names
            // have shifted across Chromium versions (PrivateNetworkAccess*
            // → LocalNetworkAccessChecks) so we list both — unknown names
            // are silently ignored by Chromium, so over-listing is safe.
            '--disable-features=LocalNetworkAccessChecks,PrivateNetworkAccessSendPreflights,PrivateNetworkAccessRespectPreflightResults,BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessPermissionPrompt',
          ],
        },
      },
    },
  ],
  // No webServer — the k8s API is already running.
});
