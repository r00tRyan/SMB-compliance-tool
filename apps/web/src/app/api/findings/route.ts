import { requireApiContext } from '@/server/auth';
import { apiOk, route } from '@/server/http';
import { listFindingsForOrg } from '@/server/tenant';

export const dynamic = 'force-dynamic';

export function GET(req: Request) {
  return route(async () => {
    const ctx = await requireApiContext();
    const q = new URL(req.url).searchParams;
    const findings = await listFindingsForOrg(ctx.organizationId, {
      severity: q.get('severity') ?? undefined,
      category: q.get('category') ?? undefined,
      status: q.get('status') ?? undefined,
      assetId: q.get('assetId') ?? undefined,
      platform: (q.get('platform') as 'windows' | 'linux' | null) ?? undefined,
    });
    return apiOk(
      findings.map((f) => ({
        id: f.id,
        checkId: f.checkId,
        severity: f.severity,
        category: f.category,
        status: f.status,
        assetId: f.assetId,
        assetName: f.asset.name,
        firstDetectedAt: f.firstDetectedAt,
        lastDetectedAt: f.lastDetectedAt,
      })),
    );
  });
}
