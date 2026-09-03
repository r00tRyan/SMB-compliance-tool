import { requireApiContext } from '@/server/auth';
import { apiOk, route } from '@/server/http';
import { getScanForOrg } from '@/server/tenant';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    const ctx = await requireApiContext();
    const scan = await getScanForOrg(ctx.organizationId, params.id);
    const tally = scan.results.reduce<Record<string, number>>((acc, r) => {
      acc[r.status] = (acc[r.status] ?? 0) + 1;
      return acc;
    }, {});
    return apiOk({
      id: scan.id,
      asset: { id: scan.asset.id, name: scan.asset.name },
      source: scan.source,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      orgScoreBefore: scan.orgScoreBefore,
      orgScoreAfter: scan.orgScoreAfter,
      resultTally: tally,
      results: scan.results.map((r) => ({
        checkId: r.checkId,
        status: r.status,
        evidence: r.evidence,
        observedAt: r.observedAt,
      })),
    });
  });
}
