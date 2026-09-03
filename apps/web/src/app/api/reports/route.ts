import { z } from 'zod';
import { assertRole, requireApiContext } from '@/server/auth';
import { apiOk, assertSameOrigin, parseJson, route, BadInputError } from '@/server/http';
import { rateLimit } from '@/server/rate-limit';
import { generateReport } from '@/server/report';
import { listReportsForOrg } from '@/server/tenant';
import { prisma } from '@/lib/prisma';

export const dynamic = 'force-dynamic';

const schema = z.object({ includeAiNarrative: z.boolean().optional() });

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const ctx = await requireApiContext();
    assertRole(ctx, ['OWNER', 'ADMIN']);
    const limit = rateLimit(`reports:${ctx.organizationId}`, 10, 60_000);
    if (!limit.ok) throw new BadInputError('Rate limit exceeded. Try again shortly.');

    const scanCount = await prisma.scan.count({ where: { organizationId: ctx.organizationId } });
    if (scanCount === 0) throw new BadInputError('Run an assessment before generating a report.');

    const body = await parseJson(req, schema).catch(() => ({ includeAiNarrative: false }));
    const { id, aiDegraded } = await generateReport(ctx, {
      includeAiNarrative: body.includeAiNarrative ?? false,
    });
    return apiOk({ id, aiDegraded }, 201);
  });
}

export function GET() {
  return route(async () => {
    const ctx = await requireApiContext();
    const reports = await listReportsForOrg(ctx.organizationId);
    return apiOk(
      reports.map((r) => ({
        id: r.id,
        title: r.title,
        orgScore: r.orgScore,
        band: r.band,
        includedAiNarrative: r.includedAiNarrative,
        aiDegraded: r.aiDegraded,
        createdAt: r.createdAt,
      })),
    );
  });
}
