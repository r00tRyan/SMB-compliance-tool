/**
 * Integration + security tests. These need a real PostgreSQL database and only
 * run when DATABASE_URL points at a *_test database (so they never touch dev
 * data). In CI that is the `postgres` service; locally:
 *   DATABASE_URL="postgresql://smb:smb@127.0.0.1:5432/smb_test?schema=public" \
 *   AUTH_SECRET="test-secret-xxxxxxxxxxxxxxxx" \
 *   pnpm --filter @smb/web exec vitest run src/server/__tests__/integration.test.ts
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const DB = process.env.DATABASE_URL ?? '';
const ENABLED = /_test(\?|$)/.test(DB) || /test/.test(new URL(DB || 'http://x').pathname);

const d = ENABLED ? describe : describe.skip;

// Imports are deferred so the pure unit run never loads Prisma/env.
let prisma: typeof import('@/lib/prisma')['prisma'];
let registerUser: typeof import('@/server/auth')['registerUser'];
let ingestScan: typeof import('@/server/ingest')['ingestScan'];
let getAssetForOrg: typeof import('@/server/tenant')['getAssetForOrg'];
let getFindingForOrg: typeof import('@/server/tenant')['getFindingForOrg'];
let computePosture: typeof import('@/server/scoring')['computePosture'];

type Ctx = {
  userId: string;
  email: string;
  organizationId: string;
  organizationName: string;
  isDemoOrg: boolean;
  role: 'OWNER' | 'ADMIN' | 'MEMBER';
};

async function makeOrg(name: string): Promise<Ctx> {
  const email = `${name.toLowerCase()}-${Date.now()}-${Math.random().toString(36).slice(2)}@example.com`;
  const { userId, organizationId } = await registerUser({
    email,
    password: 'a-strong-password-123',
    organizationName: name,
  });
  return { userId, email, organizationId, organizationName: name, isDemoOrg: false, role: 'OWNER' };
}

const scanFor = (hostname: string, checks: Array<[string, string]>) => ({
  schemaVersion: '1.0',
  asset: { hostname, platform: 'windows', osVersion: 'Windows 11' },
  scan: {
    startedAt: new Date(Date.now() - 5000).toISOString(),
    completedAt: new Date().toISOString(),
    scannerVersion: '0.1.0',
  },
  findings: checks.map(([checkId, status]) => ({
    checkId,
    status,
    evidence: `${checkId} ${status}`,
    observedAt: new Date().toISOString(),
  })),
});

d('web integration', () => {
  beforeAll(async () => {
    ({ prisma } = await import('@/lib/prisma'));
    ({ registerUser } = await import('@/server/auth'));
    ({ ingestScan } = await import('@/server/ingest'));
    ({ getAssetForOrg, getFindingForOrg } = await import('@/server/tenant'));
    ({ computePosture } = await import('@/server/scoring'));
  });

  beforeEach(async () => {
    // Wipe between tests (order respects FKs via CASCADE from Organization/User).
    await prisma.auditLog.deleteMany();
    await prisma.findingEvent.deleteMany();
    await prisma.finding.deleteMany();
    await prisma.scanResult.deleteMany();
    await prisma.scan.deleteMany();
    await prisma.asset.deleteMany();
    await prisma.membership.deleteMany();
    await prisma.report.deleteMany();
    await prisma.organization.deleteMany();
    await prisma.user.deleteMany();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('registration creates user + organization + OWNER membership', async () => {
    const ctx = await makeOrg('Acme');
    const membership = await prisma.membership.findFirstOrThrow({ where: { userId: ctx.userId } });
    expect(membership.role).toBe('OWNER');
    expect(membership.organizationId).toBe(ctx.organizationId);
  });

  it('Organization A cannot read Organization B data (tenant isolation)', async () => {
    const a = await makeOrg('OrgA');
    const b = await makeOrg('OrgB');
    const bAsset = await prisma.asset.create({
      data: { organizationId: b.organizationId, name: 'B-PC', platform: 'windows' },
    });
    await ingestScan(b, {
      assetId: bAsset.id,
      source: 'AGENT_UPLOAD',
      rawResult: scanFor('B-PC', [['WIN-FW-001', 'FAIL']]),
    });
    const bFinding = await prisma.finding.findFirstOrThrow({ where: { organizationId: b.organizationId } });

    await expect(getAssetForOrg(a.organizationId, bAsset.id)).rejects.toThrow(/not found/i);
    await expect(getFindingForOrg(a.organizationId, bFinding.id)).rejects.toThrow(/not found/i);

    // A's posture is unaffected by B's findings.
    const aPosture = await computePosture(a.organizationId);
    expect(aPosture.assetCount).toBe(0);
  });

  it('rejects a malformed scan payload', async () => {
    const ctx = await makeOrg('Malformed');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows' },
    });
    await expect(
      ingestScan(ctx, { assetId: asset.id, source: 'AGENT_UPLOAD', rawResult: { nonsense: true } }),
    ).rejects.toThrow(/validation/i);
  });

  it('rejects an unknown checkId', async () => {
    const ctx = await makeOrg('UnknownCheck');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows' },
    });
    await expect(
      ingestScan(ctx, {
        assetId: asset.id,
        source: 'AGENT_UPLOAD',
        rawResult: scanFor('PC', [['WIN-ZZZ-999', 'FAIL']]),
      }),
    ).rejects.toThrow(/unknown check id/i);
  });

  it('ignores client-supplied severity — the registry value wins', async () => {
    const ctx = await makeOrg('ForgedSeverity');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows' },
    });
    const payload = scanFor('PC', [['WIN-AUTH-002', 'FAIL']]); // registry: MEDIUM
    // Tamper: claim it is CRITICAL.
    (payload.findings[0] as Record<string, unknown>).severity = 'CRITICAL';
    (payload.findings[0] as Record<string, unknown>).category = 'made up';
    await ingestScan(ctx, { assetId: asset.id, source: 'AGENT_UPLOAD', rawResult: payload });
    const finding = await prisma.finding.findFirstOrThrow({ where: { organizationId: ctx.organizationId } });
    expect(finding.severity).toBe('MEDIUM');
    expect(finding.category).toBe('Identity & Access');
  });

  it('runs the full detect -> re-scan -> verified-resolved -> score-up loop', async () => {
    const ctx = await makeOrg('Verify');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows' },
    });

    const first = await ingestScan(ctx, {
      assetId: asset.id,
      source: 'AGENT_UPLOAD',
      rawResult: scanFor('PC', [
        ['WIN-FW-001', 'FAIL'],
        ['WIN-EPP-001', 'PASS'],
      ]),
    });
    expect(first.created).toBe(1);
    const opened = await prisma.finding.findFirstOrThrow({ where: { organizationId: ctx.organizationId } });
    expect(opened.status).toBe('OPEN');
    const scoreAfterFail = first.scoreAfter!;

    const second = await ingestScan(ctx, {
      assetId: asset.id,
      source: 'AGENT_UPLOAD',
      rawResult: scanFor('PC', [
        ['WIN-FW-001', 'PASS'],
        ['WIN-EPP-001', 'PASS'],
      ]),
    });
    expect(second.resolved).toBe(1);
    const resolved = await prisma.finding.findFirstOrThrow({ where: { id: opened.id } });
    expect(resolved.status).toBe('RESOLVED');
    expect(second.scoreAfter!).toBeGreaterThan(scoreAfterFail);

    // Audit trail recorded both scans.
    const audits = await prisma.auditLog.findMany({ where: { organizationId: ctx.organizationId } });
    expect(audits.filter((a) => a.action === 'scan.completed').length).toBe(2);
  });

  it('reopens a resolved finding on regression', async () => {
    const ctx = await makeOrg('Regression');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows' },
    });
    await ingestScan(ctx, { assetId: asset.id, source: 'AGENT_UPLOAD', rawResult: scanFor('PC', [['WIN-FW-001', 'FAIL']]) });
    await ingestScan(ctx, { assetId: asset.id, source: 'AGENT_UPLOAD', rawResult: scanFor('PC', [['WIN-FW-001', 'PASS']]) });
    const back = await ingestScan(ctx, {
      assetId: asset.id,
      source: 'AGENT_UPLOAD',
      rawResult: scanFor('PC', [['WIN-FW-001', 'FAIL']]),
    });
    expect(back.reopened).toBe(1);
    const f = await prisma.finding.findFirstOrThrow({ where: { organizationId: ctx.organizationId } });
    expect(f.status).toBe('OPEN');
  });

  it('refuses to mix demo scans with a non-demo asset', async () => {
    const ctx = await makeOrg('NoMixing');
    const asset = await prisma.asset.create({
      data: { organizationId: ctx.organizationId, name: 'PC', platform: 'windows', isDemo: false },
    });
    await expect(
      ingestScan(ctx, { assetId: asset.id, source: 'DEMO', rawResult: scanFor('PC', [['WIN-FW-001', 'FAIL']]) }),
    ).rejects.toThrow(/demo/i);
  });
});
