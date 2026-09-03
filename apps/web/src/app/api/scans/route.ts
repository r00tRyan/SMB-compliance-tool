import { z } from 'zod';
import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route, BadInputError } from '@/server/http';
import { rateLimit } from '@/server/rate-limit';
import { ingestScan } from '@/server/ingest';
import { listScansForOrg } from '@/server/tenant';
import { env } from '@/lib/env';

export const dynamic = 'force-dynamic';

const bodySchema = z.object({
  assetId: z.string().min(1),
  result: z.unknown(),
});

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();

    const limit = rateLimit(`scans:${ctx.organizationId}`, 30, 60_000);
    if (!limit.ok) throw new BadInputError('Rate limit exceeded. Try again shortly.');

    const body = await parseJson(req, bodySchema, env.SCAN_MAX_BYTES);
    const summary = await ingestScan(ctx, {
      assetId: body.assetId,
      source: 'AGENT_UPLOAD',
      rawResult: body.result,
    });
    return apiOk(summary, 201);
  });
}

export function GET(req: Request) {
  return route(async () => {
    const ctx = await requireApiContext();
    const assetId = new URL(req.url).searchParams.get('assetId') ?? undefined;
    const scans = await listScansForOrg(ctx.organizationId, assetId);
    return apiOk(
      scans.map((s) => ({
        id: s.id,
        assetId: s.assetId,
        assetName: s.asset.name,
        source: s.source,
        completedAt: s.completedAt,
        orgScoreBefore: s.orgScoreBefore,
        orgScoreAfter: s.orgScoreAfter,
      })),
    );
  });
}
