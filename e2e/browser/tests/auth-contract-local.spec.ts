// Layer-2 PR-gate auth-contract smoke. Mirrors the Layer-1 spec in
// instanode-web/e2e/auth-contract.spec.ts — but runs against a
// docker-compose-spawned api binary built from THIS PR's source code, so
// regressions are caught BEFORE merge instead of 5 minutes post-deploy.
//
// Why a second spec instead of importing the Layer-1 one?
//   1. The two specs live in different repos with different node trees and
//      different Playwright versions; pulling in the cross-repo file would
//      need a git-subtree or symlink dance that breaks the GH Actions
//      checkout model.
//   2. The Layer-1 spec asserts ACAO equals the prod web origin literally
//      ("https://instanode.dev"). Here the document origin is one of the
//      dev-only ports the router unlocks when ENVIRONMENT=development
//      (router.go ~L237 — http://localhost:5173 / :3000 / :5174). Asserting
//      against the EFFECTIVE origin keeps the contract honest under both
//      surfaces without leaking env-aware branching into the prod spec.
//
// Stack assumption: docker-compose.ci.yml is up + api healthy on
// localhost:8080. The auth-contract-compose-pw.yml workflow brings the
// stack up + waits for /healthz before invoking this test.

import { expect, test } from '@playwright/test';

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:8080';
// Use one of the ports the api unlocks in ENVIRONMENT=development. We stub
// the page itself via page.route() — no real server needs to listen here,
// only the URL bar needs to read as a cross-origin document for the browser
// to enforce CORS on the subsequent fetch.
const WEB_ORIGIN = process.env.E2E_WEB_ORIGIN ?? 'http://localhost:5173';

// Magic-link probe address. Mirrors the Layer-1 spec — the api always
// returns 202 regardless of whether the email exists or downstream send
// succeeds (anti-enumeration). The stack has no Brevo / Resend config so
// the send leg no-ops, which is the point: this test exercises the API
// contract, not delivery.
const PROBE_EMAIL = 'probe-pr-gate-local@instanode.dev';

test.describe('AUTH-004 CORS contract — Layer-2 (docker-compose) PR-gate', () => {
  test.describe.configure({ mode: 'serial' });

  // Test 1 — CORS preflight contract.
  //
  // The 2026-05-29 regression shipped a preflight WITHOUT ACAC. In Layer-2
  // we'd catch it on the PR by inspecting the live preflight response from
  // the compose-built api binary. Asserts both ACAO=WEB_ORIGIN and
  // ACAC=true on the OPTIONS reply.
  test('preflight returns ACAO=<web_origin> and ACAC=true', async ({ request }) => {
    const resp = await request.fetch(`${API_URL}/auth/exchange`, {
      method: 'OPTIONS',
      headers: {
        Origin: WEB_ORIGIN,
        'Access-Control-Request-Method': 'POST',
      },
      failOnStatusCode: false,
    });

    // Fiber's CORS middleware replies 204 on a successful preflight; allow
    // 200 in case the framework's defaults shift.
    expect(
      [200, 204].includes(resp.status()),
      `expected 200 or 204 preflight status, got ${resp.status()} — body: ${await resp.text().catch(() => '<unreadable>')}`,
    ).toBe(true);

    const headers = resp.headers();
    const acao = headers['access-control-allow-origin'];
    const acac = headers['access-control-allow-credentials'];

    expect(
      acao,
      `MISSING access-control-allow-origin on preflight for ${WEB_ORIGIN}. ` +
        `This is exactly the 2026-05-29 regression shape — the browser would refuse to ` +
        `surface the api's response and the user gets "Failed to fetch". Make sure ` +
        `the CORS allowlist still includes ${WEB_ORIGIN} (dev-only ports are appended ` +
        `in router.go when ENVIRONMENT=development).`,
    ).toBe(WEB_ORIGIN);

    expect(
      acac,
      `MISSING access-control-allow-credentials: true on preflight. The SPA fetches ` +
        `/auth/exchange with credentials:'include' to send the instanode_session_exchange ` +
        `cookie cross-origin. Without ACAC the browser drops the cookie and the api ` +
        `returns 400 cookie_missing_or_expired. Re-add AllowCredentials:true to the ` +
        `fiberCORS config (router.go).`,
    ).toBe('true');
  });

  // Test 2 — Real browser cross-origin POST completes the CORS traversal.
  //
  // Load-bearing assertion: a real Chromium page rooted at WEB_ORIGIN
  // fetches API_URL/auth/exchange. We don't care about the response status
  // (400 is expected — no bridge cookie), only that the fetch RESOLVES
  // rather than throwing "TypeError: Failed to fetch" the way the
  // 2026-05-30 prod outage did.
  test('cross-origin POST from web origin completes the CORS traversal', async ({ page }) => {
    // Serve a stub page at WEB_ORIGIN so the browser adopts it as the
    // document origin. We never let the request hit the network — there's
    // nothing listening on :5173 in this stack.
    await page.route(`${WEB_ORIGIN}/__auth_contract_origin_stub`, async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: '<!doctype html><html><body>auth-contract layer-2 stub</body></html>',
      });
    });
    const navResp = await page.goto(`${WEB_ORIGIN}/__auth_contract_origin_stub`, {
      waitUntil: 'load',
    });
    expect(
      navResp,
      `failed to navigate to ${WEB_ORIGIN} origin stub — Playwright returned no response.`,
    ).not.toBeNull();
    const docOrigin = await page.evaluate(() => window.location.origin);
    expect(
      docOrigin,
      `document origin after navigation was ${docOrigin}, expected ${WEB_ORIGIN}. ` +
        `The fetch below would not be cross-origin and the test would silently pass ` +
        `even with a broken CORS contract.`,
    ).toBe(WEB_ORIGIN);

    const result = await page.evaluate(
      async ({ apiUrl }) => {
        try {
          // Mirror instanode-web's LoginCallbackPage.tsx
          // exchangeCookieForToken EXACTLY: no custom headers, no Accept,
          // no Content-Type so it stays a "simple cross-origin request"
          // and dodges a preflight. credentials:'include' so the browser
          // would attach the bridge cookie if it had one.
          const resp = await fetch(`${apiUrl}/auth/exchange`, {
            method: 'POST',
            credentials: 'include',
          });
          const body = await resp.text().catch(() => '');
          return { ok: true, status: resp.status, bodyLen: body.length };
        } catch (e: any) {
          return { ok: false, error: String(e?.message ?? e) };
        }
      },
      { apiUrl: API_URL },
    );

    expect(
      result.ok,
      `cross-origin POST threw — this is the EXACT user-visible login failure shape. ` +
        `Browser error: ${'error' in result ? result.error : ''}. ` +
        `Likely cause: api CORS middleware dropped access-control-allow-credentials ` +
        `or access-control-allow-origin for ${WEB_ORIGIN}.`,
    ).toBe(true);

    if ('status' in result) {
      expect(
        result.status >= 400 && result.status < 500,
        `expected 4xx (cookie missing/expired) on a no-cookie exchange, got ${result.status}. ` +
          `200 would mean the api accepted an exchange with no bridge cookie — a major ` +
          `auth bug. 5xx would mean the api is unhealthy in the compose stack.`,
      ).toBe(true);
    }
  });

  // Test 3 — Magic-link start endpoint returns 202 {ok:true}.
  //
  // The handler always returns 202 (anti-enumeration). This stack has no
  // email backend wired so the send leg silently no-ops — that's fine, we
  // only assert the API contract here. Email DELIVERY is the worker
  // auth-probe's job, not this gate's.
  test('POST /auth/email/start returns 202 {ok:true}', async ({ request }) => {
    const resp = await request.fetch(`${API_URL}/auth/email/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: WEB_ORIGIN,
      },
      data: JSON.stringify({
        email: PROBE_EMAIL,
        // Use a return_to that's on the dev-allowed scheme list
        // (handlers/magic_link.go returnToSchemeIsAllowed — http://localhost
        // is permitted in non-prod via SetReturnToAllowsLocalhost in
        // router.go L512).
        return_to: `${WEB_ORIGIN}/login/callback`,
      }),
      failOnStatusCode: false,
    });

    expect(
      resp.status(),
      `POST /auth/email/start MUST always return 202 (anti-enumeration). ` +
        `Got ${resp.status()}. Body: ${await resp.text().catch(() => '<unreadable>')}`,
    ).toBe(202);

    const body = await resp.json().catch(() => null);
    expect(body, `/auth/email/start response body was not JSON`).not.toBeNull();
    expect(
      body?.ok,
      `/auth/email/start should return {ok:true}; got ${JSON.stringify(body)}`,
    ).toBe(true);
  });
});
