import type { ScanRunResult } from './runner.js';

const MARK: Record<string, string> = {
  PASS: '[PASS]',
  FAIL: '[FAIL]',
  WARN: '[WARN]',
  ERROR: '[ERR ]',
  NOT_APPLICABLE: '[N/A ]',
};

/** Human-readable terminal summary. */
export function formatReadable(run: ScanRunResult, verbose = false): string {
  const { result, checks } = run;
  const lines: string[] = [];
  lines.push('Security Assessment');
  lines.push(
    `Asset: ${result.asset.hostname}   Platform: ${result.asset.platform}   OS: ${result.asset.osVersion}`,
  );
  lines.push('');

  for (const { check, status, evidence } of checks) {
    lines.push(`${MARK[status] ?? '[????]'} ${check.id}  ${check.name}`);
    if (verbose || status === 'FAIL' || status === 'WARN' || status === 'ERROR') {
      lines.push(`        ${evidence}`);
    }
  }

  const tally = checks.reduce<Record<string, number>>((acc, c) => {
    acc[c.status] = (acc[c.status] ?? 0) + 1;
    return acc;
  }, {});
  lines.push('');
  lines.push(
    `Summary:  ${tally.PASS ?? 0} passed   ${tally.FAIL ?? 0} failed   ${tally.WARN ?? 0} warning   ${
      tally.ERROR ?? 0
    } error   ${tally.NOT_APPLICABLE ?? 0} n/a`,
  );
  if (run.collectorErrors.length > 0) {
    lines.push('');
    lines.push('Collectors that could not run (reported as ERROR above):');
    for (const e of run.collectorErrors) lines.push(`  - ${e.id}: ${e.error}`);
  }
  return lines.join('\n');
}
