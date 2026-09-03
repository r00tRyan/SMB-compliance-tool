import Link from 'next/link';
import { requireContext } from '@/server/auth';
import { addAssetAction, runDemoScanAction } from '@/app/actions';
import { listAssetsForOrg, activeFindingsForOrg } from '@/server/tenant';
import { ActionForm, SubmitButton } from '@/components/form';
import { AsyncButton } from '@/components/async-button';
import { EmptyState } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function AssetsPage() {
  const ctx = await requireContext();
  const [assets, active] = await Promise.all([
    listAssetsForOrg(ctx.organizationId),
    activeFindingsForOrg(ctx.organizationId),
  ]);
  const openByAsset = new Map<string, number>();
  for (const f of active) openByAsset.set(f.assetId, (openByAsset.get(f.assetId) ?? 0) + 1);

  return (
    <div className="space-y-6">
      <div className="card">
        <h2 className="font-semibold">Add an asset</h2>
        <ActionForm action={addAssetAction} className="mt-3 grid gap-3 sm:grid-cols-4 sm:items-end">
          <div className="sm:col-span-2">
            <label className="label" htmlFor="name">Name</label>
            <input id="name" name="name" className="input" placeholder="ACME-PC-04" required />
          </div>
          <div>
            <label className="label" htmlFor="platform">Platform</label>
            <select id="platform" name="platform" className="input">
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
          </div>
          <SubmitButton>Add asset</SubmitButton>
        </ActionForm>
      </div>

      {assets.length === 0 ? (
        <EmptyState title="No assets yet." hint="Add your first computer above to begin your security assessment." />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-muted">
              <tr>
                <th className="py-2">Name</th>
                <th>Platform</th>
                <th>Open findings</th>
                <th>Last scan</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {assets.map((a) => (
                <tr key={a.id}>
                  <td className="py-2">
                    <Link className="text-brand" href={`/assets/${a.id}`}>{a.name}</Link>
                  </td>
                  <td>{a.platform}</td>
                  <td>{openByAsset.get(a.id) ?? 0}</td>
                  <td>{a.lastScanAt ? new Date(a.lastScanAt).toLocaleString('en-US', { dateStyle: 'short' }) : '—'}</td>
                  <td>{a.status}</td>
                  <td className="text-right">
                    {ctx.isDemoOrg ? (
                      <AsyncButton action={runDemoScanAction.bind(null, a.id, [])} className="btn-ghost py-1.5">
                        Run demo scan
                      </AsyncButton>
                    ) : (
                      <span className="text-xs text-muted">upload via agent</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
