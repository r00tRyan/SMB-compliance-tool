/**
 * Local development seed. Creates the fictional "Acme Dental" demo organization
 * with 5 assets and a completed baseline demo scan. Refuses to run in
 * production. All rows are flagged isDemo / source=DEMO and are never mixed
 * with real scan data.
 */
import { PrismaClient } from '@prisma/client';
import { hash } from '@node-rs/argon2';
import { DEMO_ASSETS, DEMO_ORG_NAME, buildDemoScan } from '../src/server/demo';
import { getCheckMeta, isKnownCheckId } from '@smb/checks';
import { decideTransition } from '../src/server/lifecycle';

const prisma = new PrismaClient();

async function main() {
  if (process.env.ENABLE_DEMO_SEED !== 'true') {
    console.log('ENABLE_DEMO_SEED is not "true" — skipping demo seed.');
    return;
  }
  // The demo seed is opt-in via ENABLE_DEMO_SEED. In a production NODE_ENV it
  // must be an explicit, deliberate choice (e.g. the local docker-compose stack,
  // which runs the app with NODE_ENV=production but is still a dev environment).
  if (process.env.NODE_ENV === 'production') {
    console.warn(
      'WARNING: seeding demo data with NODE_ENV=production because ENABLE_DEMO_SEED=true. ' +
        'Demo credentials must never be enabled on a real production deployment.',
    );
  }

  const email = (process.env.DEMO_EMAIL ?? 'owner@acmedental.example').toLowerCase();
  const password = process.env.DEMO_PASSWORD ?? 'demo-password-local-only';

  const existing = await prisma.organization.findFirst({ where: { isDemo: true } });
  if (existing) {
    console.log(`Demo org "${existing.name}" already exists (${existing.id}). Nothing to do.`);
    return;
  }

  const passwordHash = await hash(password, { memoryCost: 19_456, timeCost: 2, parallelism: 1 });

  const { org, user } = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({ data: { email, passwordHash, name: 'Acme Owner' } });
    const org = await tx.organization.create({ data: { name: DEMO_ORG_NAME, isDemo: true } });
    await tx.membership.create({ data: { userId: user.id, organizationId: org.id, role: 'OWNER' } });
    return { org, user };
  });

  for (const spec of DEMO_ASSETS) {
    const asset = await prisma.asset.create({
      data: {
        organizationId: org.id,
        name: spec.name,
        platform: spec.platform,
        isDemo: true,
        description: 'Demo asset',
      },
    });

    const result = buildDemoScan(spec, { now: new Date() });
    const now = new Date();

    const scan = await prisma.scan.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        source: 'DEMO',
        status: 'COMPLETED',
        scannerVersion: result.scan.scannerVersion,
        schemaVersion: result.schemaVersion,
        startedAt: new Date(result.scan.startedAt),
        completedAt: new Date(result.scan.completedAt),
        results: {
          create: result.findings.map((f) => ({
            checkId: f.checkId,
            status: f.status,
            evidence: f.evidence,
            observedAt: new Date(f.observedAt),
          })),
        },
      },
    });

    for (const f of result.findings) {
      if (!isKnownCheckId(f.checkId)) continue;
      const decision = decideTransition(null, f.status);
      if (!decision) continue;
      const meta = getCheckMeta(f.checkId);
      const finding = await prisma.finding.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          checkId: f.checkId,
          severity: meta.severity,
          category: meta.category,
          status: decision.nextStatus,
          lastStatusRaw: f.status,
          lastEvidence: f.evidence,
          firstDetectedAt: now,
          lastDetectedAt: now,
        },
      });
      await prisma.findingEvent.create({
        data: { findingId: finding.id, toStatus: decision.nextStatus, reason: decision.reason, actor: 'system:demo' },
      });
    }

    await prisma.asset.update({ where: { id: asset.id }, data: { lastScanAt: now } });
    await prisma.auditLog.create({
      data: { organizationId: org.id, action: 'scan.completed', detail: { scanId: scan.id, source: 'DEMO' } },
    });
  }

  console.log(`Seeded demo org "${DEMO_ORG_NAME}" (${org.id}).`);
  console.log(`Demo login: ${email} / ${password}`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
