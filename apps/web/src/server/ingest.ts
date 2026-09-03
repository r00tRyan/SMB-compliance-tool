import 'server-only';
import type { ScanSource } from '@prisma/client';
import { getCheckMeta, isKnownCheckId } from '@smb/checks';
import { SecurityScanResultSchema, type SecurityScanResult } from '@smb/shared';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';
import { BadInputError } from '@/server/http';
import { decideTransition } from '@/server/lifecycle';
import { computePosture } from '@/server/scoring';
import { getAssetForOrg } from '@/server/tenant';
import type { ActiveContext } from '@/server/auth';

export interface IngestSummary {
  scanId: string;
  created: number;
  resolved: number;
  reopened: number;
  unchanged: number;
  errored: number;
  scoreBefore: number | null;
  scoreAfter: number | null;
}

/**
 * The scan-ingestion trust boundary. `rawResult` is UNTRUSTED. We:
 *  1. strictly validate the shape,
 *  2. reject unknown check ids,
 *  3. take severity/category from the server-side registry, NOT the upload,
 *  4. upsert findings through the deterministic lifecycle,
 *  5. recompute the score and write audit rows.
 */
export async function ingestScan(
  ctx: ActiveContext,
  input: { assetId: string; source: ScanSource; rawResult: unknown },
): Promise<IngestSummary> {
  const parsed = SecurityScanResultSchema.safeParse(input.rawResult);
  if (!parsed.success) {
    throw new BadInputError(
      'Scan result failed validation: ' +
        parsed.error.issues.slice(0, 5).map((i) => `${i.path.join('.')} ${i.message}`).join('; '),
    );
  }
  const result: SecurityScanResult = parsed.data;

  const unknown = result.findings.filter((f) => !isKnownCheckId(f.checkId)).map((f) => f.checkId);
  if (unknown.length > 0) {
    throw new BadInputError(`Unknown check id(s): ${[...new Set(unknown)].join(', ')}`);
  }

  const asset = await getAssetForOrg(ctx.organizationId, input.assetId);
  if (asset.platform !== result.asset.platform) {
    throw new BadInputError(
      `Scan platform "${result.asset.platform}" does not match asset platform "${asset.platform}".`,
    );
  }
  if (asset.isDemo && input.source !== 'DEMO') {
    throw new BadInputError('Demo assets only accept demo scans.');
  }
  if (!asset.isDemo && input.source === 'DEMO') {
    throw new BadInputError('Demo scans can only target demo assets.');
  }

  const postureBefore = await computePosture(ctx.organizationId);

  const summary = await prisma.$transaction(async (tx) => {
    const scan = await tx.scan.create({
      data: {
        organizationId: ctx.organizationId,
        assetId: asset.id,
        source: input.source,
        status: 'COMPLETED',
        scannerVersion: result.scan.scannerVersion,
        schemaVersion: result.schemaVersion,
        startedAt: new Date(result.scan.startedAt),
        completedAt: new Date(result.scan.completedAt),
        orgScoreBefore: postureBefore.score,
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

    const counts = { created: 0, resolved: 0, reopened: 0, unchanged: 0, errored: 0 };
    const now = new Date();

    for (const f of result.findings) {
      if (f.status === 'ERROR') counts.errored += 1;
      const meta = getCheckMeta(f.checkId); // authoritative severity/category
      const existing = await tx.finding.findUnique({
        where: { assetId_checkId: { assetId: asset.id, checkId: f.checkId } },
      });
      const decision = decideTransition(existing?.status ?? null, f.status);
      if (!decision) continue; // passing + no prior finding

      if (!existing) {
        const created = await tx.finding.create({
          data: {
            organizationId: ctx.organizationId,
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
        await tx.findingEvent.create({
          data: {
            findingId: created.id,
            fromStatus: null,
            toStatus: decision.nextStatus,
            reason: decision.reason,
            actor: input.source === 'DEMO' ? 'system:demo' : 'system:ingestion',
          },
        });
        counts.created += 1;
        continue;
      }

      const statusChanged = decision.nextStatus !== existing.status;
      await tx.finding.update({
        where: { id: existing.id },
        data: {
          severity: meta.severity, // keep authoritative values fresh
          category: meta.category,
          status: decision.nextStatus,
          previousStatus: statusChanged ? existing.status : existing.previousStatus,
          lastStatusRaw: f.status,
          lastEvidence: f.evidence,
          lastDetectedAt: now,
          resolvedAt: decision.nextStatus === 'RESOLVED' ? now : null,
          resolvedById: decision.nextStatus === 'RESOLVED' ? null : existing.resolvedById,
        },
      });
      if (statusChanged) {
        await tx.findingEvent.create({
          data: {
            findingId: existing.id,
            fromStatus: existing.status,
            toStatus: decision.nextStatus,
            reason: decision.reason,
            actor: input.source === 'DEMO' ? 'system:demo' : 'system:ingestion',
          },
        });
        if (decision.reason === 'verified_resolved') counts.resolved += 1;
        else if (decision.reason === 'regression_reopened') counts.reopened += 1;
      } else {
        counts.unchanged += 1;
      }
    }

    await tx.asset.update({ where: { id: asset.id }, data: { lastScanAt: now } });
    return { scanId: scan.id, ...counts };
  });

  const postureAfter = await computePosture(ctx.organizationId);
  await prisma.scan.update({
    where: { id: summary.scanId },
    data: { orgScoreAfter: postureAfter.score },
  });

  await writeAudit({
    organizationId: ctx.organizationId,
    userId: ctx.userId,
    action: 'scan.completed',
    detail: {
      scanId: summary.scanId,
      assetId: asset.id,
      source: input.source,
      created: summary.created,
      resolved: summary.resolved,
      reopened: summary.reopened,
      scoreBefore: postureBefore.score,
      scoreAfter: postureAfter.score,
    },
  });

  return {
    ...summary,
    scoreBefore: postureBefore.score,
    scoreAfter: postureAfter.score,
  };
}
