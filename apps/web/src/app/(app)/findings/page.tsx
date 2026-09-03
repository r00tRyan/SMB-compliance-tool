import Link from 'next/link';
import { requireContext } from '@/server/auth';
import { listFindingsForOrg } from '@/server/tenant';
import { SeverityBadge, StatusPill, EmptyState } from '@/components/ui';

export const dynamic = 'force-dynamic';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES = ['OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'];

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: { severity?: string; status?: string; platform?: string };
}) {
  const ctx = await requireContext();
  const findings = await listFindingsForOrg(ctx.organizationId, {
    severity: searchParams.severity,
    status: searchParams.status,
    platform: searchParams.platform as 'windows' | 'linux' | undefined,
  });

  const qs = (patch: Record<string, string | undefined>) => {
    const p = new URLSearchParams({ ...searchParams, ...patch } as Record<string, string>);
    for (const [k, v] of Object.entries(patch)) if (!v) p.delete(k);
    return `/findings?${p.toString()}`;
  };

  return (
    <div className="space-y-4">
      <div className="card flex flex-wrap gap-4 text-sm">
        <div>
          <span className="label">Severity</span>
          <div className="flex gap-1">
            <Link className="btn-ghost py-1" href={qs({ severity: undefined })}>All</Link>
            {SEVERITIES.map((s) => (
              <Link key={s} className={`btn-ghost py-1 ${searchParams.severity === s ? 'bg-brand-soft' : ''}`} href={qs({ severity: s })}>
                {s}
              </Link>
            ))}
          </div>
        </div>
        <div>
          <span className="label">Status</span>
          <div className="flex flex-wrap gap-1">
            <Link className="btn-ghost py-1" href={qs({ status: undefined })}>All</Link>
            {STATUSES.map((s) => (
              <Link key={s} className={`btn-ghost py-1 ${searchParams.status === s ? 'bg-brand-soft' : ''}`} href={qs({ status: s })}>
                {s.replace('_', ' ')}
              </Link>
            ))}
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <EmptyState title="No security issues match this filter." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-muted">
              <tr>
                <th className="py-2">Severity</th>
                <th>Finding</th>
                <th>Asset</th>
                <th>Category</th>
                <th>Status</th>
                <th>Last detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {findings.map((f) => (
                <tr key={f.id}>
                  <td className="py-2"><SeverityBadge severity={f.severity} /></td>
                  <td><Link className="text-brand" href={`/findings/${f.id}`}>{f.checkId}</Link></td>
                  <td>{f.asset.name}</td>
                  <td>{f.category}</td>
                  <td><StatusPill status={f.status} /></td>
                  <td>{new Date(f.lastDetectedAt).toLocaleDateString('en-US')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
