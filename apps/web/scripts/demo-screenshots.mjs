/**
 * Capture the README demo screenshots from a running instance.
 *
 * Prereqs: the app is up (e.g. `docker compose up`) and the demo org is seeded
 * (`ENABLE_DEMO_SEED=true`). Then, from apps/web:
 *
 *   node scripts/demo-screenshots.mjs
 *
 * Env: APP_URL (default http://localhost:3000),
 *      DEMO_EMAIL / DEMO_PASSWORD (defaults match .env.example).
 *
 * Writes PNGs to docs/screenshots/.
 */
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const BASE = process.env.APP_URL ?? 'http://localhost:3000';
const EMAIL = process.env.DEMO_EMAIL ?? 'owner@acmedental.example';
const PASSWORD = process.env.DEMO_PASSWORD ?? 'demo-password-local-only';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, '../../../docs/screenshots');

async function main() {
  await mkdir(outDir, { recursive: true });
  const browser = await chromium.launch();
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });

  const shot = (name, opts = {}) => page.screenshot({ path: resolve(outDir, name), ...opts });

  // 1. Login screen (before auth)
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await shot('01-login.png');

  // Sign in as the demo owner
  await page.fill('#email', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL(/\/dashboard/, { timeout: 15_000 });
  await page.waitForLoadState('networkidle');

  // 2. Dashboard — score, "fix these first", category scores
  await shot('02-dashboard.png');

  // 3. Findings list
  await page.goto(`${BASE}/findings`, { waitUntil: 'networkidle' });
  await shot('03-findings.png');

  // 4. Finding detail — what/why/fix/verify + CIS/NIST alignment
  await page.locator('table tbody a').first().click();
  await page.waitForURL(/\/findings\/[a-z0-9]{6,}$/, { timeout: 15_000 });
  await page.waitForLoadState('networkidle');
  await shot('04-finding-detail.png', { fullPage: true });

  // 5. Assets
  await page.goto(`${BASE}/assets`, { waitUntil: 'networkidle' });
  await shot('05-assets.png');

  // 6. Report — score, executive summary, posture, top risks, provenance tags
  await page.goto(`${BASE}/reports`, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Generate report/i }).click();
  await page.waitForURL(/\/reports\/[a-z0-9]+$/, { timeout: 20_000 });
  await page.waitForLoadState('networkidle');
  await shot('06-report.png', { clip: { x: 0, y: 0, width: 1440, height: 1500 } });

  await browser.close();
  console.log(`Wrote screenshots to ${outDir}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
