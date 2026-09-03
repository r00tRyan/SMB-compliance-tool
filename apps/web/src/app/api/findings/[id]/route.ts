import { z } from 'zod';
import { getCheck } from '@smb/checks';
import { controlsForCheck } from '@smb/compliance';
import { FINDING_STATUSES } from '@smb/shared';
import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route } from '@/server/http';
import { getFindingForOrg } from '@/server/tenant';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    const ctx = await requireApiContext();
    const f = await getFindingForOrg(ctx.organizationId, params.id);
    const check = getCheck(f.checkId);
    return apiOk({
      id: f.id,
      checkId: f.checkId,
      severity: f.severity,
      category: f.category,
      status: f.status,
      asset: { id: f.asset.id, name: f.asset.name, platform: f.asset.platform },
      evidence: f.lastEvidence,
      firstDetectedAt: f.firstDetectedAt,
      lastDetectedAt: f.lastDetectedAt,
      resolvedAt: f.resolvedAt,
      remediation: check?.remediation ?? null,
      controls: controlsForCheck(f.checkId),
      events: f.events.map((e) => ({ from: e.fromStatus, to: e.toStatus, reason: e.reason, at: e.createdAt })),
    });
  });
}

const patchSchema = z.object({
  status: z.enum(FINDING_STATUSES),
  note: z.string().max(500).optional(),
});

export function PATCH(req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    const body = await parseJson(req, patchSchema);
    const f = await getFindingForOrg(ctx.organizationId, params.id);
    if (f.status === body.status) return apiOk({ id: f.id, status: f.status });

    await prisma.$transaction([
      prisma.finding.update({
        where: { id: f.id },
        data: {
          previousStatus: f.status,
          status: body.status,
          note: body.note?.trim() || f.note,
          resolvedAt: body.status === 'RESOLVED' ? new Date() : null,
          resolvedById: body.status === 'RESOLVED' ? ctx.userId : null,
        },
      }),
      prisma.findingEvent.create({
        data: { findingId: f.id, fromStatus: f.status, toStatus: body.status, reason: 'user_status_change', actor: ctx.userId },
      }),
    ]);
    await writeAudit({
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      action: 'finding.status_changed',
      detail: { findingId: f.id, from: f.status, to: body.status },
    });
    return apiOk({ id: f.id, status: body.status });
  });
}
