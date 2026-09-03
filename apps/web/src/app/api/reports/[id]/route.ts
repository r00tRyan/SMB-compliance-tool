import { requireApiContext } from '@/server/auth';
import { apiOk, route } from '@/server/http';
import { getReportForOrg } from '@/server/tenant';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    const ctx = await requireApiContext();
    const report = await getReportForOrg(ctx.organizationId, params.id);
    return apiOk({
      id: report.id,
      title: report.title,
      orgScore: report.orgScore,
      band: report.band,
      includedAiNarrative: report.includedAiNarrative,
      aiDegraded: report.aiDegraded,
      createdAt: report.createdAt,
      snapshot: report.snapshot,
    });
  });
}
