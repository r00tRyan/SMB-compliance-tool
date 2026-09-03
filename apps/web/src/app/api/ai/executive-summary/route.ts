import { requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, route, BadInputError } from '@/server/http';
import { rateLimit } from '@/server/rate-limit';
import { buildAiInput, generateArtifact } from '@/server/ai';
import { prisma } from '@/lib/prisma';

export const dynamic = 'force-dynamic';

/**
 * Always returns 200. When AI is unavailable or its output fails validation,
 * `degraded: true` and `text` holds the deterministic fallback — the caller's
 * page never breaks. (docs/AI.md §Failure handling)
 */
export function POST() {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    const limit = rateLimit(`ai:${ctx.organizationId}`, 20, 60_000);
    if (!limit.ok) throw new BadInputError('Rate limit exceeded. Try again shortly.');

    const scanCount = await prisma.scan.count({ where: { organizationId: ctx.organizationId } });
    if (scanCount === 0) throw new BadInputError('Run an assessment before requesting an AI summary.');

    const input = await buildAiInput(ctx.organizationId, ctx.organizationName, ctx.isDemoOrg);
    const res = await generateArtifact('executive-summary', input);
    return apiOk({ text: res.text, degraded: res.degraded, model: res.model });
  });
}
