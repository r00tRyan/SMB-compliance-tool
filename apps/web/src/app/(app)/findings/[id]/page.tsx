import { notFound } from 'next/navigation';
import { getCheck } from '@smb/checks';
import { controlsForCheck } from '@smb/compliance';
import { requireContext } from '@/server/auth';
import { getFindingForOrg } from '@/server/tenant';
import { prisma } from '@/lib/prisma';
import { NotFoundError } from '@/server/http';
import { rescanFindingAction, updateFindingStatusAction, explainFindingAction } from '@/app/actions';
import { ActionForm, SubmitButton } from '@/components/form';
import { AsyncButton } from '@/components/async-button';
import { AiPanel } from '@/components/ai-panel';
import { SeverityBadge, StatusPill } from '@/components/ui';
import { FINDING_STATUSES } from '@smb/shared';

export const dynamic = 'force-dynamic';

export default async function FindingDetailPage({ params }: { params: { id: string } }) {
  const ctx = await requireContext();
  let finding;
  try {
    finding = await getFindingForOrg(ctx.organizationId, params.id);
  } catch (e) {
    if (e instanceof NotFoundError) notFound();
    throw e;
  }
  const check = getCheck(finding.checkId);
  const controls = controlsForCheck(finding.checkId);
  const alsoAffected = await prisma.finding.findMany({
    where: { organizationId: ctx.organizationId, checkId: finding.checkId },
    include: { asset: true },
  });

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-lg font-semibold">{check?.name ?? finding.checkId}</h1>
          <SeverityBadge severity={finding.severity} />
          <StatusPill status={finding.status} />
        </div>
        <p className="text-sm text-muted">
          {finding.checkId} · {finding.category} · {finding.asset.name} · first detected{' '}
          {new Date(finding.firstDetectedAt).toLocaleDateString('en-US')}
        </p>
      </div>

      <section className="card space-y-4">
        <div>
          <h2 className="font-semibold">What we found</h2>
          <p className="mt-1 text-sm">{check?.remediation.whatWeFound}</p>
          <p className="mt-1 text-xs text-muted">Observed evidence: {finding.lastEvidence}</p>
        </div>
        <div>
          <h2 className="font-semibold">Why it matters</h2>
          <p className="mt-1 text-sm">{check?.remediation.whyItMatters ?? check?.rationale}</p>
        </div>
        <div>
          <h2 className="font-semibold">Recommended fix</h2>
          <ol className="mt-1 list-decimal pl-5 text-sm space-y-1">
            {check?.remediation.recommendedFix.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
          <p className="mt-2 text-xs text-muted">
            Who: {check?.remediation.who} · Estimated effort: {check?.remediation.effort}
          </p>
          {check?.remediation.warning ? (
            <p className="mt-2 rounded bg-amber-50 p-2 text-xs text-amber-800">⚠ {check.remediation.warning}</p>
          ) : null}
        </div>
        <div>
          <h2 className="font-semibold">Verification</h2>
          <p className="mt-1 text-sm">{check?.remediation.verification}</p>
        </div>
      </section>

      <section className="card">
        <h2 className="font-semibold">Compliance alignment</h2>
        <ul className="mt-2 space-y-1 text-sm">
          {controls.map((c) => (
            <li key={`${c.framework}-${c.controlId}`}>
              <span className="font-medium">{c.framework} {c.controlId}</span> — {c.title}
              <span className="block text-xs text-muted">{c.summary}</span>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-muted">
          Control alignment only — not a determination of regulatory compliance.
        </p>
      </section>

      <section className="card">
        <h2 className="font-semibold">Affected systems</h2>
        <ul className="mt-2 text-sm">
          {alsoAffected.map((f) => (
            <li key={f.id}>
              {f.asset.name} — <StatusPill status={f.status} />
            </li>
          ))}
        </ul>
      </section>

      <section className="card space-y-3">
        <h2 className="font-semibold">Status &amp; verification</h2>
        <ActionForm action={updateFindingStatusAction} className="flex flex-wrap items-end gap-2">
          <input type="hidden" name="findingId" value={finding.id} />
          <div>
            <label className="label" htmlFor="status">Set status</label>
            <select id="status" name="status" defaultValue={finding.status} className="input">
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>{s.replace('_', ' ')}</option>
              ))}
            </select>
          </div>
          <input name="note" placeholder="Optional note" className="input max-w-xs" />
          <SubmitButton>Update</SubmitButton>
        </ActionForm>

        <div>
          <AsyncButton action={rescanFindingAction.bind(null, finding.id)}>Re-scan</AsyncButton>
          <p className="mt-1 text-xs text-muted">
            {ctx.isDemoOrg
              ? 'Re-runs the demo scan with this check fixed, so you can watch it verify as resolved.'
              : 'For live assets, upload a fresh scan from the agent (see docs/SCANNER.md).'}
          </p>
        </div>

        <AiPanel label="Explain this finding" action={explainFindingAction.bind(null, finding.id)} />
      </section>
    </div>
  );
}
