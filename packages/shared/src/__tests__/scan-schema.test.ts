import { describe, expect, it } from 'vitest';
import { SecurityScanResultSchema } from '../scan-schema.js';

const valid = {
  schemaVersion: '1.0',
  asset: { hostname: 'ACME-PC-01', platform: 'windows', osVersion: 'Windows 11 23H2' },
  scan: {
    startedAt: '2026-09-03T10:00:00.000Z',
    completedAt: '2026-09-03T10:00:12.000Z',
    scannerVersion: '0.1.0',
  },
  findings: [
    {
      checkId: 'WIN-FW-001',
      status: 'FAIL',
      evidence: 'Firewall profile Domain: Disabled',
      observedAt: '2026-09-03T10:00:05.000Z',
    },
  ],
};

describe('SecurityScanResultSchema', () => {
  it('accepts a well-formed payload', () => {
    expect(SecurityScanResultSchema.parse(valid)).toMatchObject({ schemaVersion: '1.0' });
  });

  it('rejects unknown top-level keys', () => {
    expect(() => SecurityScanResultSchema.parse({ ...valid, extra: true })).toThrow();
  });

  it('rejects a bad schema version', () => {
    expect(() => SecurityScanResultSchema.parse({ ...valid, schemaVersion: '2.0' })).toThrow();
  });

  it('rejects malformed checkId', () => {
    const bad = { ...valid, findings: [{ ...valid.findings[0], checkId: 'nope' }] };
    expect(() => SecurityScanResultSchema.parse(bad)).toThrow();
  });

  it('rejects completedAt before startedAt', () => {
    const bad = {
      ...valid,
      scan: { ...valid.scan, completedAt: '2026-09-03T09:59:00.000Z' },
    };
    expect(() => SecurityScanResultSchema.parse(bad)).toThrow(/completedAt/);
  });

  it('rejects duplicate checkIds', () => {
    const bad = { ...valid, findings: [valid.findings[0], valid.findings[0]] };
    expect(() => SecurityScanResultSchema.parse(bad)).toThrow(/duplicate/);
  });

  it('rejects an empty findings array', () => {
    expect(() => SecurityScanResultSchema.parse({ ...valid, findings: [] })).toThrow();
  });

  it('tolerates client-sent severity/category (server ignores them later)', () => {
    const withNoise = {
      ...valid,
      findings: [{ ...valid.findings[0], severity: 'CRITICAL', category: 'made up' }],
    };
    expect(SecurityScanResultSchema.parse(withNoise).findings[0]?.severity).toBe('CRITICAL');
  });
});
