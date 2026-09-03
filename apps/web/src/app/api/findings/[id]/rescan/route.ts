import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, route, BadInputError } from '@/server/http';
import { getFindingForOrg } from '@/server/tenant';
import { buildDemoScan, demoAssetSpec } from '@/server/demo';
import { ingestScan } from '@/server/ingest';

export const dynamic = 'force-dynamic';

/**
 * Re-scan a single finding's check.
 *  - Demo org: re-runs the demo scan with this check marked fixed, so the
 *    verification loop can be demonstrated end-to-end.
 *  - Live org: no server-side scan exists; the caller must upload a fresh
 *    scan from the agent (POST /api/scans). Returns 400 with that guidance.
 */
export function POST(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    const finding = await getFindingForOrg(ctx.organizationId, params.id);

    if (!ctx.isDemoOrg) {
      throw new BadInputError(
        'Live re-scan requires uploading a fresh scan from the agent (POST /api/scans). See docs/SCANNER.md.',
      );
    }
    const spec = demoAssetSpec(finding.asset.name);
    if (!spec) throw new BadInputError('No demo scenario exists for this asset.');
    const result = buildDemoScan(spec, { fixCheckIds: [finding.checkId] });
    const summary = await ingestScan(ctx, {
      assetId: finding.assetId,
      source: 'DEMO',
      rawResult: result,
    });
    const after = await getFindingForOrg(ctx.organizationId, params.id);
    return apiOk({ ...summary, findingStatus: after.status });
  });
}
