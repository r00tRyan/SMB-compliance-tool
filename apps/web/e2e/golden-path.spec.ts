import { test, expect } from '@playwright/test';

/**
 * The Definition-of-Done workflow:
 *   sign up -> org created -> add asset -> (demo) scan -> see score ->
 *   open finding -> understand it -> re-scan -> finding resolves ->
 *   score changes -> generate report -> view scan history -> audit history.
 *
 * Requires the app running against a migrated database. In CI the DB is the
 * `postgres` service; locally: `docker compose up` then `pnpm test:e2e`.
 */
test('golden path: signup through verified remediation and report', async ({ page }) => {
  const stamp = Date.now();
  const email = `owner+${stamp}@example.com`;

  // 1-3. Sign up -> organization created -> land on dashboard (empty state).
  await page.goto('/register');
  await page.fill('#organizationName', `Test Co ${stamp}`);
  await page.fill('#email', email);
  await page.fill('#password', 'a-strong-password');
  await page.click('button[type=submit]');
  await expect(page).toHaveURL(/\/dashboard/);
  await expect(page.getByText(/Add your first computer/i)).toBeVisible();

  // 4. Add an asset.
  await page.goto('/assets');
  await page.fill('#name', `TEST-PC-${stamp}`);
  await page.selectOption('#platform', 'windows');
  await page.getByRole('button', { name: 'Add asset' }).click();
  await expect(page.getByText(`TEST-PC-${stamp}`)).toBeVisible();

  // 5-7. Ingest a scan via the API and see the score appear.
  const failing = {
    schemaVersion: '1.0',
    asset: { hostname: `TEST-PC-${stamp}`, platform: 'windows', osVersion: 'Windows 11' },
    scan: {
      startedAt: new Date(Date.now() - 5000).toISOString(),
      completedAt: new Date().toISOString(),
      scannerVersion: '0.1.0',
    },
    findings: [
      { checkId: 'WIN-FW-001', status: 'FAIL', evidence: 'Domain: OFF', observedAt: new Date().toISOString() },
      { checkId: 'WIN-EPP-001', status: 'PASS', evidence: 'on', observedAt: new Date().toISOString() },
    ],
  };
  const assetId = await page
    .getByText(`TEST-PC-${stamp}`)
    .locator('xpath=ancestor::tr')
    .locator('a')
    .first()
    .getAttribute('href')
    .then((h) => h!.split('/').pop()!);

  const ingest = await page.request.post('/api/scans', {
    data: { assetId, result: failing },
    headers: { origin: page.url().replace(/\/[^/]*$/, '') },
  });
  expect(ingest.ok()).toBeTruthy();

  await page.goto('/dashboard');
  await expect(page.getByText('Security Score')).toBeVisible();
  await expect(page.getByText('Fix these first')).toBeVisible();

  // 8-13. Open the finding and read its guidance.
  await page.goto('/findings');
  await page.getByRole('link', { name: 'WIN-FW-001' }).click();
  await expect(page.getByText('What we found')).toBeVisible();
  await expect(page.getByText('Compliance alignment')).toBeVisible();
  await expect(page.getByText(/CIS Controls v8/)).toBeVisible();

  // 14-17. Re-scan with the check fixed -> finding resolves -> score improves.
  const fixed = {
    ...failing,
    scan: { ...failing.scan, completedAt: new Date().toISOString() },
    findings: [
      { checkId: 'WIN-FW-001', status: 'PASS', evidence: 'Domain: ON', observedAt: new Date().toISOString() },
      { checkId: 'WIN-EPP-001', status: 'PASS', evidence: 'on', observedAt: new Date().toISOString() },
    ],
  };
  const rescan = await page.request.post('/api/scans', {
    data: { assetId, result: fixed },
    headers: { origin: page.url().replace(/\/[^/]*$/, '') },
  });
  expect(rescan.ok()).toBeTruthy();
  const body = await rescan.json();
  expect(body.resolved).toBeGreaterThanOrEqual(1);

  await page.reload();
  await expect(page.getByText('RESOLVED').first()).toBeVisible();

  // 18-19. Generate a report (AI degrades gracefully with no key) + PDF.
  await page.goto('/reports');
  await page.getByRole('button', { name: /Generate report/i }).click();
  await expect(page).toHaveURL(/\/reports\/[a-z0-9]+$/);
  await expect(page.getByRole('heading', { name: 'Executive summary' })).toBeVisible();
  await expect(
    page.getByText(/not a legal determination of regulatory compliance/i),
  ).toBeVisible();

  const pdf = await page.request.get(page.url() + '/pdf');
  expect(pdf.headers()['content-type']).toContain('application/pdf');
  expect((await pdf.body()).length).toBeGreaterThan(1000);

  // 20-21. Scan history + audit history.
  await page.goto('/scans');
  await expect(page.getByText('AGENT_UPLOAD').first()).toBeVisible();
  await page.goto('/activity');
  await expect(page.getByText('scan.completed').first()).toBeVisible();
  await expect(page.getByText('organization.created').first()).toBeVisible();
});
