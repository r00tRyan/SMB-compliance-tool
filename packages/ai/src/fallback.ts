import type { AiArtifact, AiReportInput } from './types.js';

/**
 * Deterministic, no-AI text for every AI artifact. Used when Anthropic is not
 * configured, errors, or returns output that fails validation. The product is
 * fully usable on these alone.
 */

const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;

function topFindings(input: AiReportInput, n: number): AiReportInput['findings'] {
  return [...input.findings]
    .sort(
      (a, b) =>
        sevRank[a.severity] - sevRank[b.severity] ||
        b.affectedAssets - a.affectedAssets ||
        a.checkId.localeCompare(b.checkId),
    )
    .slice(0, n);
}

function summary(input: AiReportInput): string {
  const { counts, score, band, organization } = input;
  const highPriority = counts.critical + counts.high;
  const lead =
    `${organization} has a ${band.toLowerCase()} security posture with an assessment score of ${score} out of 100.`;
  const issues =
    highPriority > 0
      ? ` The assessment identified ${highPriority} high-priority issue${highPriority === 1 ? '' : 's'}` +
        ` (${counts.critical} critical, ${counts.high} high) alongside ${counts.medium} medium and ${counts.low} low-severity items.`
      : ` No critical or high-severity issues were identified; ${counts.medium} medium and ${counts.low} low-severity items remain.`;
  const next =
    input.findings.length > 0
      ? ` Start with: ${topFindings(input, 3)
          .map((f) => f.title)
          .join('; ')}.`
      : ' No outstanding remediation items.';
  const disclaimer =
    ' This is a posture assessment that identifies configuration gaps and maps them to recognized controls; it is not a determination of regulatory compliance.';
  return lead + issues + next + disclaimer;
}

function remediationPlan(input: AiReportInput): string {
  if (input.findings.length === 0) return 'No remediation items. Re-run the assessment periodically to catch new gaps.';
  return topFindings(input, 8)
    .map((f, i) => {
      const urgency =
        f.severity === 'CRITICAL' || f.severity === 'HIGH'
          ? 'address soon'
          : f.severity === 'MEDIUM'
            ? 'address this month'
            : 'address when convenient';
      return `${i + 1}. ${f.title} — ${f.severity}, ${f.affectedAssets} device${
        f.affectedAssets === 1 ? '' : 's'
      } affected (${urgency}). ${f.recommendedFix}`;
    })
    .join('\n');
}

function findingExplanation(input: AiReportInput): string {
  const f = input.findings[0];
  if (!f) return 'No finding supplied.';
  return (
    `What we found: ${f.whatWeFound}\n` +
    `Why it matters: this is a ${f.severity} issue in the ${f.category} area, affecting ${f.affectedAssets} device${
      f.affectedAssets === 1 ? '' : 's'
    }.\n` +
    `What to do: ${f.recommendedFix}\n` +
    `After making the change, run the assessment again to confirm the issue is resolved.`
  );
}

function reportNarrative(input: AiReportInput): string {
  return (
    `${summary(input)}\n\n` +
    `Highest-priority risks:\n${remediationPlan(input)}\n\n` +
    `Recommended next steps: work through the prioritized list above, re-run the assessment to verify each fix, ` +
    `and schedule a recurring assessment so new configuration gaps are caught early.`
  );
}

export function deterministicText(artifact: AiArtifact, input: AiReportInput): string {
  switch (artifact) {
    case 'executive-summary':
      return summary(input);
    case 'remediation-plan':
      return remediationPlan(input);
    case 'finding-explanation':
      return findingExplanation(input);
    case 'report-narrative':
      return reportNarrative(input);
    default: {
      const _exhaustive: never = artifact;
      return _exhaustive;
    }
  }
}
