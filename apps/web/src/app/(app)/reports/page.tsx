import Link from 'next/link';
import { requireContext } from '@/server/auth';
import { listReportsForOrg } from '@/server/tenant';
import { generateReportAction } from '@/app/actions';
import { ActionForm, SubmitButton } from '@/components/form';
import { aiEnabled } from '@/server/ai';

export const dynamic = 'force-dynamic';

export default async function ReportsPage() {
  const ctx = await requireContext();
  const reports = await listReportsForOrg(ctx.organizationId);

  return (
    <div className="space-y-6">
      <div className="card">
        <h2 className="font-semibold">Generate a report</h2>
        <p className="mt-1 text-sm text-muted">
          Creates an immutable snapshot of your current posture with a disclaimer, control alignment, and remediation guidance.
        </p>
        <ActionForm action={generateReportAction} className="mt-3 flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" name="includeAi" defaultChecked={aiEnabled} />
            Include AI-written narrative {aiEnabled ? '' : '(AI not configured — deterministic text will be used)'}
          </label>
          <SubmitButton>Generate report</SubmitButton>
        </ActionForm>
      </div>

      <div className="card">
        <h2 className="font-semibold">Report history</h2>
        <ul className="mt-3 divide-y divide-line text-sm">
          {reports.length === 0 ? (
            <li className="py-2 text-muted">No reports yet.</li>
          ) : (
            reports.map((r) => (
              <li key={r.id} className="flex items-center justify-between py-2">
                <Link className="text-brand" href={`/reports/${r.id}`}>{r.title}</Link>
                <span className="text-muted">
                  score {r.orgScore} · {r.band} · {new Date(r.createdAt).toLocaleString('en-US', { dateStyle: 'short' })}
                </span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
