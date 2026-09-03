import { requireApiContext } from '@/server/auth';
import { getReportForOrg } from '@/server/tenant';
import { renderReportPdf } from '@/server/report-pdf';
import { route } from '@/server/http';
import type { ReportSnapshot } from '@/server/report';
import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';

export function GET(_req: Request, { params }: { params: { id: string } }) {
  return route(async () => {
    const ctx = await requireApiContext();
    const report = await getReportForOrg(ctx.organizationId, params.id);
    const pdf = await renderReportPdf(report.snapshot as unknown as ReportSnapshot);
    return new NextResponse(new Uint8Array(pdf), {
      status: 200,
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="security-assessment-${report.id}.pdf"`,
      },
    });
  });
}
