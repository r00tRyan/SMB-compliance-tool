import Link from 'next/link';
import type { ReactNode } from 'react';

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

export function StatusPill({ status }: { status: string }) {
  const tone =
    status === 'RESOLVED'
      ? 'bg-green-50 text-sev-ok'
      : status === 'OPEN'
        ? 'bg-red-50 text-sev-critical'
        : 'bg-slate-100 text-sev-info';
  return <span className={`badge ${tone}`}>{status.replace('_', ' ')}</span>;
}

export function ScoreDial({ score, band }: { score: number | null; band: string | null }) {
  if (score == null) {
    return (
      <div className="card">
        <div className="text-sm text-muted">Security Score</div>
        <div className="mt-2 text-3xl font-bold text-muted">—</div>
        <p className="mt-1 text-sm text-muted">Run your first assessment to establish a baseline.</p>
      </div>
    );
  }
  return (
    <div className="card">
      <div className="text-sm text-muted">Security Score</div>
      <div className="mt-1 flex items-baseline gap-2">
        <span className="text-5xl font-bold">{score}</span>
        <span className="text-lg text-muted">/ 100</span>
      </div>
      <div className="mt-1 text-sm font-semibold">{band}</div>
      <p className="mt-2 text-xs text-muted">
        An internal risk indicator, not a precise measurement.
      </p>
    </div>
  );
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="card">
      <div className="text-sm text-muted">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="card text-center py-12">
      <p className="font-medium">{title}</p>
      {hint ? <p className="mt-1 text-sm text-muted">{hint}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function DemoBadge() {
  return (
    <span className="badge bg-purple-100 text-purple-700 ml-2" title="This organization contains demo data only">
      DEMO DATA
    </span>
  );
}

export function NavLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <Link href={href} className="px-3 py-2 rounded-lg text-sm hover:bg-slate-100">
      {children}
    </Link>
  );
}
