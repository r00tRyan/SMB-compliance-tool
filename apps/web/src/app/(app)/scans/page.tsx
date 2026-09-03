import { requireContext } from '@/server/auth';
import { listScansForOrg } from '@/server/tenant';
import { EmptyState } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function ScansPage() {
  const ctx = await requireContext();
  const scans = await listScansForOrg(ctx.organizationId);

  if (scans.length === 0) {
    return <EmptyState title="Run your first assessment to establish your baseline." />;
  }

  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-muted">
          <tr>
            <th className="py-2">Completed</th>
            <th>Asset</th>
            <th>Source</th>
            <th>Checks</th>
            <th>Score change</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {scans.map((s) => (
            <tr key={s.id}>
              <td className="py-2">{new Date(s.completedAt).toLocaleString('en-US')}</td>
              <td>{s.asset.name}</td>
              <td>{s.source}</td>
              <td>{s.schemaVersion}</td>
              <td>
                {s.orgScoreBefore ?? '—'} → {s.orgScoreAfter ?? '—'}{' '}
                {s.orgScoreBefore != null && s.orgScoreAfter != null ? (
                  <span className={s.orgScoreAfter >= s.orgScoreBefore ? 'text-sev-ok' : 'text-sev-high'}>
                    ({s.orgScoreAfter - s.orgScoreBefore >= 0 ? '+' : ''}
                    {s.orgScoreAfter - s.orgScoreBefore})
                  </span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
