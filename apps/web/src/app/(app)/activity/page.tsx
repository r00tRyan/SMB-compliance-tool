import { requireContext } from '@/server/auth';
import { listAuditForOrg } from '@/server/tenant';
import { EmptyState } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function ActivityPage() {
  const ctx = await requireContext();
  const rows = await listAuditForOrg(ctx.organizationId, 200);
  if (rows.length === 0) return <EmptyState title="No activity recorded yet." />;

  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-left text-muted">
          <tr>
            <th className="py-2">When</th>
            <th>Action</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="py-2 whitespace-nowrap">{new Date(r.createdAt).toLocaleString('en-US')}</td>
              <td className="font-medium">{r.action}</td>
              <td className="text-muted">{r.detail ? JSON.stringify(r.detail) : ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
