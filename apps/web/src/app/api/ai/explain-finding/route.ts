import { z } from 'zod';
import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route, BadInputError } from '@/server/http';
import { rateLimit } from '@/server/rate-limit';
import { buildAiInput, generateArtifact, narrowToFinding } from '@/server/ai';
import { getFindingForOrg } from '@/server/tenant';

export const dynamic = 'force-dynamic';

const schema = z.object({ findingId: z.string().min(1) });

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    const limit = rateLimit(`ai:${ctx.organizationId}`, 20, 60_000);
    if (!limit.ok) throw new BadInputError('Rate limit exceeded. Try again shortly.');
    const body = await parseJson(req, schema);
    const finding = await getFindingForOrg(ctx.organizationId, body.findingId);
    const input = await buildAiInput(ctx.organizationId, ctx.organizationName, ctx.isDemoOrg);
    const res = await generateArtifact('finding-explanation', narrowToFinding(input, finding.id));
    return apiOk({ text: res.text, degraded: res.degraded, model: res.model });
  });
}
