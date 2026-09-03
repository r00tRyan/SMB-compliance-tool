import { describe, expect, it } from 'vitest';
import { allChecks } from '@smb/checks';
import {
  computeCoverage,
  controlsForCheck,
  mappedFrameworks,
  unmappedRegistryControls,
  type CheckAssessment,
} from '../index.js';

describe('control catalog integrity', () => {
  it('every framework mapping in the check registry has a catalog entry', () => {
    expect(unmappedRegistryControls()).toEqual([]);
  });

  it('maps both CIS Controls v8 and NIST CSF 2.0', () => {
    expect(mappedFrameworks()).toEqual(['CIS Controls v8', 'NIST CSF 2.0']);
  });
});

describe('computeCoverage', () => {
  const allCheckIds = allChecks.map((c) => c.id);

  it('marks controls NOT_ASSESSED when nothing has run', () => {
    const cov = computeCoverage([]);
    for (const fw of cov) {
      expect(fw.assessedControls).toBe(0);
      expect(fw.rows.every((r) => r.status === 'NOT_ASSESSED')).toBe(true);
    }
  });

  it('marks a control ALIGNED when all mapped checks passed', () => {
    const assessments: CheckAssessment[] = allCheckIds.map((checkId) => ({
      checkId,
      assessed: true,
      failing: false,
    }));
    const cov = computeCoverage(assessments);
    for (const fw of cov) {
      expect(fw.alignedControls).toBe(fw.totalControls);
      expect(fw.controlsWithGaps).toBe(0);
    }
  });

  it('marks a control GAPS when any mapped check is failing', () => {
    // WIN-FW-001 maps to CIS 4.5 and NIST PR.IR-01
    const assessments: CheckAssessment[] = allCheckIds.map((checkId) => ({
      checkId,
      assessed: true,
      failing: checkId === 'WIN-FW-001',
    }));
    const cov = computeCoverage(assessments);
    const cis = cov.find((f) => f.framework === 'CIS Controls v8')!;
    const row = cis.rows.find((r) => r.controlId === '4.5')!;
    expect(row.status).toBe('GAPS');
    expect(row.failingChecks).toBeGreaterThan(0);
    expect(row.mappedCheckIds).toContain('WIN-FW-001');
  });

  it('is deterministic and stably ordered', () => {
    const a = JSON.stringify(computeCoverage([]));
    const b = JSON.stringify(computeCoverage([]));
    expect(a).toBe(b);
  });
});

describe('controlsForCheck', () => {
  it('returns the catalog controls a check aligns to', () => {
    const controls = controlsForCheck('LNX-SSH-001');
    expect(controls.length).toBeGreaterThanOrEqual(2);
    expect(controls.map((c) => c.framework)).toContain('CIS Controls v8');
    expect(controls.map((c) => c.framework)).toContain('NIST CSF 2.0');
  });

  it('returns nothing for an unknown check', () => {
    expect(controlsForCheck('ZZZ-ZZ-000')).toEqual([]);
  });
});
