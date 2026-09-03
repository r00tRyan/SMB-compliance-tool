import { describe, expect, it } from 'vitest';
import { CATEGORIES, SEVERITIES } from '@smb/shared';
import {
  allChecks,
  assertKnownCheckId,
  getCheck,
  getCheckMeta,
  isKnownCheckId,
  listChecks,
  UnknownCheckError,
} from '../index.js';

describe('check registry', () => {
  it('registers a meaningful number of checks across both platforms', () => {
    expect(allChecks.length).toBeGreaterThanOrEqual(20);
    expect(listChecks('windows').length).toBeGreaterThanOrEqual(10);
    expect(listChecks('linux').length).toBeGreaterThanOrEqual(8);
  });

  it('every check is well-formed', () => {
    for (const c of allChecks) {
      expect(c.id).toMatch(/^[A-Z]{3}-[A-Z0-9]{2,6}-\d{3}$/);
      expect(SEVERITIES).toContain(c.severity);
      expect(CATEGORIES).toContain(c.category);
      expect(c.collectors.length).toBeGreaterThan(0);
      expect(c.rationale.length).toBeGreaterThan(20);
      expect(c.remediation.recommendedFix.length).toBeGreaterThan(0);
      expect(c.remediation.verification.length).toBeGreaterThan(10);
      expect(c.frameworks.length).toBeGreaterThan(0);
      expect(c.frameworks.some((f) => f.framework.startsWith('CIS'))).toBe(true);
      expect(c.frameworks.some((f) => f.framework.startsWith('NIST'))).toBe(true);
      expect(c.references.length).toBeGreaterThan(0);
      expect(c.autoRemediationSupported).toBe(false);
      expect(typeof c.evaluate).toBe('function');
    }
  });

  it('has no duplicate ids', () => {
    const ids = allChecks.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('getCheckMeta returns metadata without evaluate and is authoritative', () => {
    const meta = getCheckMeta('WIN-FW-001');
    expect(meta.severity).toBe('HIGH');
    expect(meta).not.toHaveProperty('evaluate');
  });

  it('rejects unknown check ids', () => {
    expect(isKnownCheckId('WIN-XXX-999')).toBe(false);
    expect(() => getCheckMeta('WIN-XXX-999')).toThrow(UnknownCheckError);
    expect(() => assertKnownCheckId('nope')).toThrow(UnknownCheckError);
    expect(getCheck('nope')).toBeUndefined();
  });
});
