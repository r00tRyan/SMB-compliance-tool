import Link from 'next/link';
import { requireContext } from '@/server/auth';
import { computePosture } from '@/server/scoring';
import { listAuditForOrg } from '@/server/tenant';
import { ScoreDial, Stat, EmptyState, SeverityBadge } from '@/components/ui';

export const dynamic = 'force-dynamic';

export default async function DashboardPage() {
  const ctx = await requireContext();
  const [posture, activity] = await Promise.all([
    computePosture(ctx.organizationId),
    listAuditForOrg(ctx.organizationId, 8),
  ]);

  if (posture.assetCount === 0) {
    return (
      <EmptyState
        title="Add your first computer to begin your security assessment."
        hint="Register a Windows or Linux endpoint, then run a scan (or a demo scan) to establish your baseline."
        action={<Link href="/assets" className="btn-primary">Add an asset</Link>}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-4">
        <ScoreDial score={posture.score} band={posture.band} />
        <Stat label="Critical" value={posture.counts.critical} />
        <Stat label="High" value={posture.counts.high} />
        <Stat label="Medium / Low" value={`${posture.counts.medium} / ${posture.counts.low}`} />
      </div>

      <section className="card">
        <h2 className="font-semibold">Fix these first</h2>
        {posture.priorities.length === 0 ? (
          <p className="mt-2 text-sm text-muted">No outstanding priorities. Nice work.</p>
        ) : (
          <ol className="mt-3 divide-y divide-line">
            {posture.priorities.slice(0, 5).map((p) => (
              <li key={p.checkId} className="flex items-center justify-between py-2">
                <div>
                  <div className="font-medium">
                    {p.rank}. {p.checkName}
                  </div>
                  <div className="text-xs text-muted">
                    {p.affectedAssets} device{p.affectedAssets === 1 ? '' : 's'} · est. effort: {p.effortLabel}
                  </div>
                </div>
                <SeverityBadge severity={p.severity} />
              </li>
            ))}
          </ol>
        )}
      </section>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="card">
          <h2 className="font-semibold">Security categories</h2>
          <ul className="mt-3 space-y-2">
            {posture.categories.map((c) => (
              <li key={c.category} className="flex items-center justify-between text-sm">
                <span>{c.category}</span>
                <span className="font-semibold">{c.score ?? '—'}</span>
              </li>
            ))}
          </ul>
        </section>

        <section className="card">
          <h2 className="font-semibold">Recent activity</h2>
          <ul className="mt-3 space-y-1 text-sm text-muted">
            {activity.length === 0 ? (
              <li>No activity yet.</li>
            ) : (
              activity.map((a) => (
                <li key={a.id}>
                  {a.action.replace(/[._]/g, ' ')} ·{' '}
                  {new Date(a.createdAt).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' })}
                </li>
              ))
            )}
          </ul>
        </section>
      </div>

      <p className="text-xs text-muted">
        This score is an internal risk indicator, not a determination of regulatory compliance.
      </p>
    </div>
  );
}
