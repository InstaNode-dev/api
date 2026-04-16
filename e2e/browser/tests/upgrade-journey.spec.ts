/**
 * The Upgrade Journey — U1 through U9
 *
 * Simulates a developer who:
 *  1. Has an AI agent provision anonymous cache (via real k8s API)
 *  2. Sees the upgrade URL in their logs
 *  3. Opens the URL in a browser (Playwright drives a real Chrome)
 *  4. Fills in their email and creates a free account
 *  5. Sees the success state
 *
 * Target: real k8s cluster at E2E_API_URL (default: http://localhost:30080)
 * No mocks — Playwright hits the actual server.
 */

import { test, expect, Page } from '@playwright/test';
import {
  provisionAnonymousCache,
  extractUpgradeURL,
  extractJWT,
  uniqueIP,
  uniqueEmail,
} from './helpers';

// Collect console errors from the page.
async function withConsoleTracking(page: Page): Promise<string[]> {
  const errors: string[] = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') errors.push(msg.text());
  });
  page.on('pageerror', (err) => errors.push(err.message));
  return errors;
}

// ── U1: Navigate to /start?t=JWT — page loads, no JS errors ─────────────────

test('U1: onboarding page loads without JS errors', async ({ page }) => {
  const consoleErrors = await withConsoleTracking(page);

  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);

  await page.goto(upgradeURL);
  await page.waitForLoadState('networkidle');

  // No JS errors.
  expect(consoleErrors, `JS errors on page: ${consoleErrors.join(', ')}`).toHaveLength(0);

  // Page title includes instant.dev branding.
  const title = await page.title();
  expect(title.toLowerCase()).toContain('instant');
});

// ── U2: Onboarding page structure — form visible ─────────────────────────────

test('U2: onboarding page has claim form and email input', async ({ page }) => {
  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);

  await page.goto(upgradeURL);

  // Form must be present.
  await expect(page.locator('#claim-form')).toBeVisible();

  // Email input must be present and focused/ready.
  const emailInput = page.locator('#email');
  await expect(emailInput).toBeVisible();
  await expect(emailInput).toBeEnabled();

  // Submit button must be present.
  const submitBtn = page.locator('#submit-btn');
  await expect(submitBtn).toBeVisible();
  await expect(submitBtn).toBeEnabled();
});

// ── U3: Resource information shown on page ───────────────────────────────────

test('U3: onboarding page shows resource information', async ({ page }) => {
  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);

  await page.goto(upgradeURL);

  // Page should mention "free resources" or "resource" — indicates JWT was decoded.
  const bodyText = await page.locator('body').innerText();
  const hasResourceContext =
    bodyText.toLowerCase().includes('resource') ||
    bodyText.toLowerCase().includes('cache') ||
    bodyText.toLowerCase().includes('redis') ||
    bodyText.toLowerCase().includes('free') ||
    bodyText.includes(anonCache.token);

  expect(hasResourceContext).toBeTruthy();
});

// ── U4: Invalid email → submit shows error, button re-enables ────────────────

test('U4: invalid email shows error message', async ({ page }) => {
  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);

  await page.goto(upgradeURL);

  // Type an invalid email (no @).
  await page.locator('#email').fill('notanemail');

  // Press Enter to submit — more reliable than clicking the submit button
  // in headless Chromium for forms served by a non-Vite server.
  await page.locator('#email').press('Enter');

  // Wait for JS to run and update the DOM.
  await page.waitForTimeout(500);

  // Error message must become visible (JS sets display:block on #error-msg).
  const errorMsg = page.locator('#error-msg');
  await expect(errorMsg).toBeVisible({ timeout: 5000 });

  const errorText = await errorMsg.innerText();
  expect(errorText.length).toBeGreaterThan(0);

  // Button must remain enabled (not disabled — only set on valid submission).
  await expect(page.locator('#submit-btn')).toBeEnabled();
});

// ── U5 + U6: Valid email → submit → success state ────────────────────────────

test('U5+U6: valid email creates account and shows success state', async ({ page }) => {
  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);
  const email = uniqueEmail();

  await page.goto(upgradeURL);

  // Fill valid email and submit.
  await page.locator('#email').fill(email);
  await page.locator('#submit-btn').click();

  // Wait for success state — the form hides, success box appears.
  await expect(page.locator('#success-box')).toBeVisible({ timeout: 10000 });

  // Form section must be hidden.
  const formSection = page.locator('#form-section');
  await expect(formSection).toBeHidden();

  // Success box must have meaningful content.
  const successText = await page.locator('#success-box').innerText();
  expect(successText.length).toBeGreaterThan(5);
});

// ── U7: Already-claimed JWT → /start shows "already claimed" page ────────────

test('U7: already-claimed JWT renders already-claimed page (no form)', async ({ page }) => {
  const ip = uniqueIP();
  const anonCache = await provisionAnonymousCache(ip);
  const upgradeURL = extractUpgradeURL(anonCache.note);
  const email1 = uniqueEmail();

  // First claim via direct API (not browser) to set up already-claimed state.
  const jwt = extractJWT(anonCache.note);
  const claimResp = await fetch(
    (process.env.E2E_API_URL ?? 'http://localhost:30080') + '/claim',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jwt, email: email1 }),
    },
  );
  expect(claimResp.status).toBe(201);

  // Now open the browser with the same URL.
  // The server returns buildAlreadyClaimedHTML() — a different page, no claim form.
  await page.goto(upgradeURL);
  await page.waitForLoadState('networkidle');

  // The form must NOT be shown (JWT already consumed).
  const formVisible = await page.locator('#claim-form').isVisible();
  expect(formVisible).toBeFalsy();

  // Page must render something meaningful — not blank.
  const bodyText = await page.locator('body').innerText();
  expect(bodyText.trim().length).toBeGreaterThan(10);

  // Should contain some indication that it's already been used.
  const hasClaimedIndicator =
    bodyText.toLowerCase().includes('already') ||
    bodyText.toLowerCase().includes('claimed') ||
    bodyText.toLowerCase().includes('account') ||
    bodyText.toLowerCase().includes('dashboard') ||
    bodyText.toLowerCase().includes('log in');
  expect(hasClaimedIndicator).toBeTruthy();
});

// ── U8: /start with no ?t= → graceful render, not blank/500 ─────────────────

test('U8: /start with no token param renders gracefully', async ({ page }) => {
  const apiURL = process.env.E2E_API_URL ?? 'http://localhost:30080';
  const resp = await page.goto(`${apiURL}/start`);

  // Must not be a 500.
  expect(resp?.status()).not.toBe(500);

  // Page must have some content (not blank).
  const bodyText = await page.locator('body').innerText();
  expect(bodyText.trim().length).toBeGreaterThan(0);
});

// ── U9: /start?t= with expired-looking JWT → graceful error state ────────────

test('U9: tampered/invalid JWT renders error state, not blank page', async ({ page }) => {
  const apiURL = process.env.E2E_API_URL ?? 'http://localhost:30080';
  const fakeJWT =
    'eyJhbGciOiJIUzI1NiJ9.eyJmcCI6ImZha2UiLCJ0b2siOltdLCJleHAiOjF9.invalidsig';

  const resp = await page.goto(`${apiURL}/start?t=${fakeJWT}`);

  // Must not be 500.
  expect(resp?.status()).not.toBe(500);

  // Page must render content — not blank.
  const bodyText = await page.locator('body').innerText();
  expect(bodyText.trim().length).toBeGreaterThan(0);
});
