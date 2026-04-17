/**
 * Shared helpers for browser E2E tests.
 *
 * These call the REAL k8s API (not mocked) to provision resources
 * and extract upgrade URLs — then hand the URLs to Playwright.
 */

const API_URL = process.env.E2E_API_URL ?? 'http://localhost:30080';

export interface AnonymousCacheProvision {
  ok: boolean;
  token: string;
  tier: string;
  limits: Record<string, unknown>;
  note: string;
}

export interface ClaimResult {
  ok: boolean;
  team_id: string;
  user_id: string;
}

/**
 * Provision anonymous Redis cache from the live k8s API (POST /cache/new).
 * Returns the full response body (includes upgrade JWT in `note`).
 */
export async function provisionAnonymousCache(ip?: string): Promise<AnonymousCacheProvision> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (ip) headers['X-Forwarded-For'] = ip;

  const resp = await fetch(`${API_URL}/cache/new`, { method: 'POST', headers });
  if (!resp.ok && resp.status !== 201) {
    throw new Error(`POST /cache/new failed: ${resp.status}`);
  }
  return resp.json() as Promise<AnonymousCacheProvision>;
}

/**
 * Provision an anonymous Postgres DB from the live k8s API.
 * Returns null if the service returns 503 (not yet enabled).
 */
export async function provisionDB(ip?: string): Promise<Record<string, unknown> | null> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (ip) headers['X-Forwarded-For'] = ip;

  const resp = await fetch(`${API_URL}/db/new`, { method: 'POST', headers });
  if (resp.status === 503) return null;
  if (resp.status !== 201) throw new Error(`POST /db/new failed: ${resp.status}`);
  return resp.json() as Promise<Record<string, unknown>>;
}

/**
 * Provision an anonymous Redis cache from the live k8s API.
 * Returns null if the service returns 503 (not yet enabled).
 */
export async function provisionCache(ip?: string): Promise<Record<string, unknown> | null> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (ip) headers['X-Forwarded-For'] = ip;

  const resp = await fetch(`${API_URL}/cache/new`, { method: 'POST', headers });
  if (resp.status === 503) return null;
  if (resp.status !== 201) throw new Error(`POST /cache/new failed: ${resp.status}`);
  return resp.json() as Promise<Record<string, unknown>>;
}

/**
 * Extract the /start?t=JWT URL from the note field of a provision response.
 */
export function extractUpgradeURL(note: string): string {
  const marker = '/start?t=';
  const idx = note.indexOf(marker);
  if (idx === -1) throw new Error(`No upgrade URL found in note: ${note}`);
  let url = note.slice(idx);
  // Trim trailing whitespace/newline.
  const spaceIdx = url.search(/\s/);
  if (spaceIdx !== -1) url = url.slice(0, spaceIdx);
  // Make absolute if it's a relative path.
  if (url.startsWith('/start')) {
    return `${API_URL}${url}`;
  }
  // Replace production hostname with test server URL.
  return url.replace(/https?:\/\/[^/]+/, API_URL);
}

/**
 * Extract just the JWT from the note field.
 */
export function extractJWT(note: string): string {
  const url = extractUpgradeURL(note);
  const tIdx = url.indexOf('?t=');
  if (tIdx === -1) throw new Error(`No ?t= param in URL: ${url}`);
  return url.slice(tIdx + 3);
}

/**
 * Generate a unique random IP in 10.x.x.x range.
 */
export function uniqueIP(): string {
  const b = () => Math.floor(Math.random() * 254) + 1;
  return `10.${b()}.${b()}.${b()}`;
}

/**
 * Generate a unique test email.
 */
export function uniqueEmail(): string {
  return `browser-e2e-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@instanode.dev`;
}
