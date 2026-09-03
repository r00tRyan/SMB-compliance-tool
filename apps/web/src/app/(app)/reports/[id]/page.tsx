import { notFound } from 'next/navigation';
import { requireContext } from '@/server/auth';
import { getReportForOrg } from '@/server/tenant';
import { NotFoundError } from '@/server/http';
import type { ReportSnapshot } from '@/server/report';

export const dynamic = 'force-dynamic';

function Tag({ p }: { p: string }) {
  const map: Record<string, string> = {
    observed: 'bg-slate-100 text-slate-600',
    assessed: 'bg-sky-50 text-sky-700',
    recommended: 'bg-emerald-50 text-emerald-700',
    'ai-generated': 'bg-violet-50 text-violet-700',
    mixed: 'bg-slate-100 text-slate-600',
  };
  return <span className={`badge ${map[p] ?? 'bg-slate-100'}`}>{p}</span>;
}

export default async function ReportDetailPage({ params }: { params: { id: string } }) {
  const ctx = await requireContext();
  let report;
  try {
    report = await getReportForOrg(ctx.organizationId, params.id);
  } catch (e) {
    if (e instanceof NotFoundError) notFound();
    throw e;
  }
  const s = report.snapshot as unknown as ReportSnapshot;

  return (
    <article className="space-y-6">
      <header className="card">
        <h1 className="text-xl font-bold">{report.title}</h1>
        <p className="text-sm text-muted">
          {s.organization}
          {s.isDemo ? ' · DEMO DATA' : ''} · generated {new Date(s.generatedAt).toLocaleString('en-US')}
        </p>
        <p className="mt-3 text-3xl font-bold">
          {s.score} <span className="text-base font-normal text-muted">/ 100 · {s.band}</span>
        </p>
        <a className="btn-ghost mt-3 inline-block" href={`/reports/${report.id}/pdf`}>Download PDF</a>
      </header>

      <section className="card">
        <div className="flex items-center gap-2">
          <h2 className="font-semibold">Executive summary</h2>
          <Tag p={s.executiveSummary.provenance} />
        </div>
        <p className="mt-2 whitespace-pre-wrap text-sm">{s.executiveSummary.text}</p>
      </section>

      <section className="card">
        <h2 className="font-semibold">Security posture <Tag p="assessed" /></h2>
        <ul className="mt-2 grid grid-cols-2 gap-2 text-sm sm:grid-cols-3">
          {s.posture.categories.map((c) => (
            <li key={c.category} className="flex justify-between border-b border-line py-1">
              <span>{c.category}</span>
              <span className="font-semibold">{c.score ?? '—'}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2 className="font-semibold">Top risks <Tag p="assessed" /></h2>
        <ol className="mt-2 list-decimal pl-5 text-sm space-y-1">
          {s.topRisks.items.map((r) => (
            <li key={r.rank}>
              {r.title} — {r.severity}, {r.affectedAssets} device(s), effort {r.effortLabel}
            </li>
          ))}
        </ol>
      </section>

      <section className="card">
        <h2 className="font-semibold">Detailed findings</h2>
        <div className="mt-2 space-y-4 text-sm">
          {s.findings.items.map((f) => (
            <div key={f.checkId} className="border-b border-line pb-3">
              <p className="font-medium">{f.title} — {f.severity}</p>
              <p><Tag p="observed" /> {f.observed}</p>
              <p><Tag p="assessed" /> {f.assessed}</p>
              <p><Tag p="recommended" /> {f.recommended.join(' ')}</p>
              <p className="text-xs text-muted">Verification: {f.verification}</p>
              <p className="text-xs text-muted">{f.controls.join(' · ')}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <h2 className="font-semibold">Control alignment <Tag p="assessed" /></h2>
        <ul className="mt-2 text-sm">
          {s.controlAlignment.frameworks.map((fw) => (
            <li key={fw.framework}>
              {fw.framework}: {fw.aligned} aligned, {fw.gaps} with gaps, {fw.notAssessed} not assessed (of {fw.total})
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2 className="font-semibold">Narrative</h2>
        <Tag p={s.narrative.provenance} />
        <p className="mt-2 whitespace-pre-wrap text-sm">{s.narrative.text}</p>
      </section>

      <section className="card text-xs text-muted">
        <p><strong>Methodology.</strong> {s.methodology.text}</p>
        <p className="mt-2"><strong>Limitations.</strong> {s.limitations.text}</p>
        <p className="mt-2"><strong>Disclaimer.</strong> {s.disclaimer}</p>
      </section>
    </article>
  );
}
