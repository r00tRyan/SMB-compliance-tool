import { z } from 'zod';
import { assertRole, requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route } from '@/server/http';
import { listAssetsForOrg, activeFindingsForOrg } from '@/server/tenant';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';

export const dynamic = 'force-dynamic';

export function GET() {
  return route(async () => {
    const ctx = await requireApiContext();
    const [assets, active] = await Promise.all([
      listAssetsForOrg(ctx.organizationId),
      activeFindingsForOrg(ctx.organizationId),
    ]);
    const open = new Map<string, number>();
    for (const f of active) open.set(f.assetId, (open.get(f.assetId) ?? 0) + 1);
    return apiOk(
      assets.map((a) => ({
        id: a.id,
        name: a.name,
        platform: a.platform,
        status: a.status,
        openFindings: open.get(a.id) ?? 0,
        lastScanAt: a.lastScanAt,
      })),
    );
  });
}

const createSchema = z.object({
  name: z.string().min(1).max(120),
  platform: z.enum(['windows', 'linux']),
  description: z.string().max(500).optional(),
});

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    assertRole(ctx, ['OWNER', 'ADMIN']);
    const body = await parseJson(req, createSchema);
    const asset = await prisma.asset.create({
      data: {
        organizationId: ctx.organizationId,
        name: body.name.trim(),
        platform: body.platform,
        description: body.description?.trim() || null,
        isDemo: ctx.isDemoOrg,
      },
    });
    await writeAudit({
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      action: 'asset.created',
      detail: { assetId: asset.id },
    });
    return apiOk({ id: asset.id, name: asset.name, platform: asset.platform }, 201);
  });
}
