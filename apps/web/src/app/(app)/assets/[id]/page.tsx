import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireContext } from '@/server/auth';
import { getAssetForOrg, listScansForOrg, listFindingsForOrg } from '@/server/tenant';
import { runDemoScanAction } from '@/app/actions';
import { AsyncButton } from '@/components/async-button';
import { SeverityBadge, StatusPill } from '@/components/ui';
import { NotFoundError } from '@/server/http';

export const dynamic = 'force-dynamic';

export default async function AssetDetailPage({ params }: { params: { id: string } }) {
  const ctx = await requireContext();
  let asset;
  try {
    asset = await getAssetForOrg(ctx.organizationId, params.id);
  } catch (e) {
    if (e instanceof NotFoundError) notFound();
    throw e;
  }
  const [scans, findings] = await Promise.all([
    listScansForOrg(ctx.organizationId, asset.id),
    listFindingsForOrg(ctx.organizationId, { assetId: asset.id }),
  ]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{asset.name}</h1>
          <p className="text-sm text-muted">
            {asset.platform} · {asset.description ?? 'no description'} ·{' '}
            {asset.lastScanAt ? `last scan ${new Date(asset.lastScanAt).toLocaleString('en-US')}` : 'never scanned'}
          </p>
        </div>
        {ctx.isDemoOrg ? (
          <AsyncButton action={runDemoScanAction.bind(null, asset.id, [])}>Run demo scan</AsyncButton>
        ) : null}
      </div>

      <section className="card">
        <h2 className="font-semibold">Findings ({findings.length})</h2>
        <ul className="mt-3 divide-y divide-line">
          {findings.length === 0 ? (
            <li className="py-2 text-sm text-muted">No findings for this asset yet.</li>
          ) : (
            findings.map((f) => (
              <li key={f.id} className="flex items-center justify-between py-2 text-sm">
                <Link className="text-brand" href={`/findings/${f.id}`}>
                  {f.checkId} — {f.category}
                </Link>
                <span className="flex items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <StatusPill status={f.status} />
                </span>
              </li>
            ))
          )}
        </ul>
      </section>

      <section className="card">
        <h2 className="font-semibold">Scan history</h2>
        <ul className="mt-3 divide-y divide-line text-sm">
          {scans.length === 0 ? (
            <li className="py-2 text-muted">No scans yet.</li>
          ) : (
            scans.map((s) => (
              <li key={s.id} className="flex justify-between py-2">
                <span>
                  {new Date(s.completedAt).toLocaleString('en-US')} · {s.source}
                </span>
                <span className="text-muted">
                  score {s.orgScoreBefore ?? '—'} → {s.orgScoreAfter ?? '—'}
                </span>
              </li>
            ))
          )}
        </ul>
      </section>
    </div>
  );
}
