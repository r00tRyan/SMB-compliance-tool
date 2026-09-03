import { z } from 'zod';
import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route, BadInputError } from '@/server/http';
import { getAssetForOrg } from '@/server/tenant';
import { buildDemoScan, demoAssetSpec } from '@/server/demo';
import { ingestScan } from '@/server/ingest';

export const dynamic = 'force-dynamic';

const schema = z.object({
  assetId: z.string().min(1),
  fixCheckIds: z.array(z.string()).max(50).optional(),
});

/** Run a demo scan for a demo asset (optionally marking checks fixed). */
export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    if (!ctx.isDemoOrg) throw new BadInputError('Demo scans are only available in a demo organization.');
    const body = await parseJson(req, schema);
    const asset = await getAssetForOrg(ctx.organizationId, body.assetId);
    const spec = demoAssetSpec(asset.name);
    if (!spec) throw new BadInputError('No demo scenario exists for this asset.');
    const result = buildDemoScan(spec, { fixCheckIds: body.fixCheckIds });
    const summary = await ingestScan(ctx, { assetId: asset.id, source: 'DEMO', rawResult: result });
    return apiOk(summary, 201);
  });
}
