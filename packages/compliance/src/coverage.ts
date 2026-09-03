import { allChecks, getCheck } from '@smb/checks';
import { CONTROL_CATALOG, getControl, type ControlDefinition } from './catalog.js';

/** Per-check assessment state supplied by the caller (derived from findings). */
export interface CheckAssessment {
  checkId: string;
  /** a scan has run this check on at least one asset */
  assessed: boolean;
  /** there is at least one active (failing) finding for this check */
  failing: boolean;
}

export type ControlStatus = 'ALIGNED' | 'GAPS' | 'NOT_ASSESSED';

export interface ControlCoverageRow extends ControlDefinition {
  mappedCheckIds: string[];
  status: ControlStatus;
  assessedChecks: number;
  failingChecks: number;
}

export interface FrameworkCoverage {
  framework: string;
  totalControls: number;
  assessedControls: number;
  alignedControls: number;
  controlsWithGaps: number;
  rows: ControlCoverageRow[];
}

/** framework -> controlId -> checkIds, built once from the check registry. */
const controlToChecks: Map<string, Map<string, string[]>> = (() => {
  const m = new Map<string, Map<string, string[]>>();
  for (const check of allChecks) {
    for (const fm of check.frameworks) {
      if (!m.has(fm.framework)) m.set(fm.framework, new Map());
      const inner = m.get(fm.framework)!;
      inner.set(fm.controlId, [...(inner.get(fm.controlId) ?? []), check.id]);
    }
  }
  return m;
})();

/** All framework names that at least one check maps to. */
export function mappedFrameworks(): string[] {
  return [...controlToChecks.keys()].sort();
}

/**
 * Compute control alignment for one organization.
 *
 * A control is ALIGNED when every check mapped to it has been assessed and none
 * are failing; GAPS when at least one mapped check is failing; NOT_ASSESSED when
 * no mapped check has run yet. This is *control alignment*, not certification.
 */
export function computeCoverage(assessments: CheckAssessment[]): FrameworkCoverage[] {
  const byCheck = new Map(assessments.map((a) => [a.checkId, a]));

  return mappedFrameworks().map((framework) => {
    const controls = controlToChecks.get(framework)!;
    const rows: ControlCoverageRow[] = [];

    for (const [controlId, checkIds] of [...controls.entries()].sort((a, b) =>
      a[0].localeCompare(b[0], undefined, { numeric: true }),
    )) {
      const def =
        getControl(framework, controlId) ??
        ({ framework, controlId, title: controlId, summary: 'No catalog entry.' } as ControlDefinition);

      const states = checkIds.map((id) => byCheck.get(id));
      const assessedChecks = states.filter((s) => s?.assessed).length;
      const failingChecks = states.filter((s) => s?.failing).length;

      let status: ControlStatus;
      if (failingChecks > 0) status = 'GAPS';
      else if (assessedChecks === 0) status = 'NOT_ASSESSED';
      else status = 'ALIGNED';

      rows.push({
        ...def,
        mappedCheckIds: [...checkIds].sort(),
        status,
        assessedChecks,
        failingChecks,
      });
    }

    return {
      framework,
      totalControls: rows.length,
      assessedControls: rows.filter((r) => r.status !== 'NOT_ASSESSED').length,
      alignedControls: rows.filter((r) => r.status === 'ALIGNED').length,
      controlsWithGaps: rows.filter((r) => r.status === 'GAPS').length,
      rows,
    };
  });
}

/** Which catalog controls a single finding's check aligns to (for finding detail). */
export function controlsForCheck(checkId: string): ControlDefinition[] {
  const check = getCheck(checkId);
  if (!check) return [];
  return check.frameworks
    .map((fm) => getControl(fm.framework, fm.controlId))
    .filter((c): c is ControlDefinition => Boolean(c));
}

/** Guard used by tests: every registry mapping must resolve to a catalog entry. */
export function unmappedRegistryControls(): string[] {
  const missing: string[] = [];
  for (const [framework, controls] of controlToChecks) {
    for (const controlId of controls.keys()) {
      if (!getControl(framework, controlId)) missing.push(`${framework}::${controlId}`);
    }
  }
  return missing;
}

export { CONTROL_CATALOG };
