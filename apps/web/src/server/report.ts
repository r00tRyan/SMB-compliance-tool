import 'server-only';
import { getCheck } from '@smb/checks';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';
import { buildAiInput, generateArtifact } from '@/server/ai';
import { computeOrgCoverage, computePosture } from '@/server/scoring';
import { activeFindingsForOrg } from '@/server/tenant';
import type { ActiveContext } from '@/server/auth';

export const REPORT_DISCLAIMER =
  'This assessment identifies security configuration gaps and provides control-alignment guidance. ' +
  'It is not a legal determination of regulatory compliance, certification, or audit readiness. ' +
  'Results reflect the state of the assessed systems at the time of the scan and depend on the checks performed; ' +
  'absence of a finding is not a guarantee that no risk exists.';

/** Every report section is tagged with the provenance of its content. */
export type Provenance = 'observed' | 'assessed' | 'recommended' | 'ai-generated';

export interface ReportSnapshot {
  generatedAt: string;
  organization: string;
  isDemo: boolean;
  score: number;
  band: string;
  disclaimer: string;
  executiveSummary: { provenance: Provenance; text: string };
  posture: {
    provenance: 'assessed';
    score: number;
    band: string;
    categories: { category: string; score: number | null }[];
    counts: { critical: number; high: number; medium: number; low: number };
  };
  topRisks: {
    provenance: 'assessed';
    items: { rank: number; title: string; severity: string; affectedAssets: number; effortLabel: string }[];
  };
  findings: {
    provenance: 'mixed';
    items: {
      checkId: string;
      title: string;
      severity: string;
      category: string;
      status: string;
      affectedAssets: number;
      observed: string; // evidence sample
      assessed: string;
      recommended: string[];
      verification: string;
      controls: string[];
    }[];
  };
  controlAlignment: {
    provenance: 'assessed';
    frameworks: { framework: string; aligned: number; gaps: number; notAssessed: number; total: number }[];
  };
  methodology: { provenance: 'assessed'; text: string };
  limitations: { provenance: 'assessed'; text: string };
  narrative: { provenance: Provenance; text: string };
}

export async function generateReport(
  ctx: ActiveContext,
  opts: { includeAiNarrative: boolean },
): Promise<{ id: string; snapshot: ReportSnapshot; aiDegraded: boolean }> {
  const [posture, coverage, active] = await Promise.all([
    computePosture(ctx.organizationId),
    computeOrgCoverage(ctx.organizationId),
    activeFindingsForOrg(ctx.organizationId),
  ]);

  // aggregate findings by check
  const byCheck = new Map<string, { count: number; evidence: string; status: string; severity: string; category: string }>();
  for (const f of active) {
    const e = byCheck.get(f.checkId);
    if (e) e.count += 1;
    else
      byCheck.set(f.checkId, {
        count: 1,
        evidence: f.lastEvidence,
        status: f.status,
        severity: f.severity,
        category: f.category,
      });
  }

  const aiInput = await buildAiInput(ctx.organizationId, ctx.organizationName, ctx.isDemoOrg);
  let aiDegraded = true;
  let summaryText: string;
  let narrativeText: string;

  if (opts.includeAiNarrative) {
    const [summary, narrative] = await Promise.all([
      generateArtifact('executive-summary', aiInput),
      generateArtifact('report-narrative', aiInput),
    ]);
    summaryText = summary.text;
    narrativeText = narrative.text;
    aiDegraded = summary.degraded || narrative.degraded;
  } else {
    const [summary, narrative] = await Promise.all([
      generateArtifact('executive-summary', { ...aiInput }),
      generateArtifact('report-narrative', { ...aiInput }),
    ]);
    // deterministic path still runs through the client, which returns fallbacks
    summaryText = summary.text;
    narrativeText = narrative.text;
    aiDegraded = true;
  }

  const score = posture.score ?? 100;
  const band = posture.band ?? 'Excellent';

  const snapshot: ReportSnapshot = {
    generatedAt: new Date().toISOString(),
    organization: ctx.organizationName,
    isDemo: ctx.isDemoOrg,
    score,
    band,
    disclaimer: REPORT_DISCLAIMER,
    executiveSummary: {
      provenance: opts.includeAiNarrative && !aiDegraded ? 'ai-generated' : 'assessed',
      text: summaryText,
    },
    posture: {
      provenance: 'assessed',
      score,
      band,
      categories: posture.categories.map((c) => ({ category: c.category, score: c.score })),
      counts: posture.counts,
    },
    topRisks: {
      provenance: 'assessed',
      items: posture.priorities.slice(0, 10).map((p) => ({
        rank: p.rank,
        title: p.checkName,
        severity: p.severity,
        affectedAssets: p.affectedAssets,
        effortLabel: p.effortLabel,
      })),
    },
    findings: {
      provenance: 'mixed',
      items: [...byCheck.entries()]
        .sort(
          (a, b) =>
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(a[1].severity) -
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(b[1].severity),
        )
        .map(([checkId, agg]) => {
          const check = getCheck(checkId);
          return {
            checkId,
            title: check?.name ?? checkId,
            severity: agg.severity,
            category: agg.category,
            status: agg.status,
            affectedAssets: agg.count,
            observed: agg.evidence,
            assessed: `Status FAIL · Severity ${agg.severity} · Category ${agg.category}`,
            recommended: check?.remediation.recommendedFix ?? [],
            verification: check?.remediation.verification ?? '',
            controls: (check?.frameworks ?? []).map((fm) => `${fm.framework} ${fm.controlId} — ${fm.controlName}`),
          };
        }),
    },
    controlAlignment: {
      provenance: 'assessed',
      frameworks: coverage.map((fw) => ({
        framework: fw.framework,
        aligned: fw.alignedControls,
        gaps: fw.controlsWithGaps,
        notAssessed: fw.totalControls - fw.assessedControls,
        total: fw.totalControls,
      })),
    },
    methodology: {
      provenance: 'assessed',
      text:
        'Read-only configuration checks were run against each registered endpoint (Windows and Linux). ' +
        'The scanner reports observed configuration only; it performs no exploitation, credential access, or network scanning. ' +
        'Status and severity are assigned by deterministic application logic from a fixed check registry.',
    },
    limitations: {
      provenance: 'assessed',
      text:
        'Coverage is limited to the checks in the current registry and to endpoints that have been scanned. ' +
        'The assessment is point-in-time. No network, cloud, identity-provider, or application-layer testing was performed. ' +
        'Checks that could not be evaluated are recorded as errors rather than passes.',
    },
    narrative: {
      provenance: opts.includeAiNarrative && !aiDegraded ? 'ai-generated' : 'assessed',
      text: narrativeText,
    },
  };

  const report = await prisma.report.create({
    data: {
      organizationId: ctx.organizationId,
      title: `Security Assessment — ${new Date().toLocaleDateString('en-US', { dateStyle: 'medium' })}`,
      orgScore: score,
      band,
      snapshot: snapshot as unknown as object,
      includedAiNarrative: opts.includeAiNarrative,
      aiDegraded,
      createdById: ctx.userId,
    },
  });

  await writeAudit({
    organizationId: ctx.organizationId,
    userId: ctx.userId,
    action: opts.includeAiNarrative ? 'report.generated_with_ai' : 'report.generated',
    detail: { reportId: report.id, score, aiDegraded },
  });

  return { id: report.id, snapshot, aiDegraded };
}
