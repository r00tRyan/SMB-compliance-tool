import { z } from 'zod';
import { assertRole, requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route } from '@/server/http';
import { getAssetForOrg, listScansForOrg, listFindingsForOrg } from '@/server/tenant';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    const ctx = await requireApiContext();
    const asset = await getAssetForOrg(ctx.organizationId, params.id);
    const [scans, findings] = await Promise.all([
      listScansForOrg(ctx.organizationId, asset.id),
      listFindingsForOrg(ctx.organizationId, { assetId: asset.id }),
    ]);
    return apiOk({
      id: asset.id,
      name: asset.name,
      platform: asset.platform,
      description: asset.description,
      status: asset.status,
      isDemo: asset.isDemo,
      lastScanAt: asset.lastScanAt,
      openFindings: findings.filter((f) => !['RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'].includes(f.status)).length,
      findings: findings.map((f) => ({ id: f.id, checkId: f.checkId, severity: f.severity, status: f.status })),
      scanHistory: scans.map((s) => ({
        id: s.id,
        completedAt: s.completedAt,
        source: s.source,
        orgScoreBefore: s.orgScoreBefore,
        orgScoreAfter: s.orgScoreAfter,
      })),
    });
  });
}

const patchSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  description: z.string().max(500).nullable().optional(),
  status: z.enum(['ACTIVE', 'ARCHIVED']).optional(),
});

export function PATCH(req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    assertRole(ctx, ['OWNER', 'ADMIN']);
    const asset = await getAssetForOrg(ctx.organizationId, params.id);
    const body = await parseJson(req, patchSchema);
    const updated = await prisma.asset.update({
      where: { id: asset.id },
      data: {
        ...(body.name !== undefined ? { name: body.name.trim() } : {}),
        ...(body.description !== undefined ? { description: body.description?.trim() || null } : {}),
        ...(body.status !== undefined ? { status: body.status } : {}),
      },
    });
    await writeAudit({
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      action: 'asset.updated',
      detail: { assetId: asset.id },
    });
    return apiOk({ id: updated.id, name: updated.name, status: updated.status });
  });
}

export function DELETE(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    assertRole(ctx, ['OWNER', 'ADMIN']);
    const asset = await getAssetForOrg(ctx.organizationId, params.id);
    await prisma.asset.delete({ where: { id: asset.id } });
    await writeAudit({
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      action: 'asset.deleted',
      detail: { assetId: asset.id, name: asset.name },
    });
    return apiOk({ ok: true });
  });
}
