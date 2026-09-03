import { describe, expect, it } from 'vitest';
import type { Category, FindingStatus, Severity } from '@smb/shared';
import { bandFor, computeOrgScore, prioritize } from '../index.js';
import type { PrioritizableFinding, ScoredFinding } from '../index.js';

const f = (
  over: Partial<ScoredFinding> & { severity: Severity; assetId: string },
): ScoredFinding => ({
  checkId: over.checkId ?? 'WIN-FW-001',
  category: (over.category ?? 'Network Security') as Category,
  status: (over.status ?? 'OPEN') as FindingStatus,
  ...over,
});

describe('computeOrgScore', () => {
  it('returns null for an org with no assets', () => {
    const r = computeOrgScore([], []);
    expect(r.score).toBeNull();
    expect(r.band).toBeNull();
  });

  it('is 100 with assets and no findings', () => {
    const r = computeOrgScore([], ['a', 'b']);
    expect(r.score).toBe(100);
    expect(r.band).toBe('Excellent');
  });

  it('deducts severity penalties per asset and averages', () => {
    // asset a: one HIGH (-20) -> 80 ; asset b: clean -> 100 ; mean -> 90
    const r = computeOrgScore([f({ severity: 'HIGH', assetId: 'a' })], ['a', 'b']);
    expect(r.score).toBe(90);
  });

  it('is deterministic and order-independent', () => {
    const findings = [
      f({ severity: 'HIGH', assetId: 'a', checkId: 'WIN-FW-001' }),
      f({ severity: 'MEDIUM', assetId: 'a', checkId: 'WIN-AUTH-002', category: 'Identity & Access' }),
      f({ severity: 'CRITICAL', assetId: 'b', checkId: 'WIN-SMB-001' }),
    ];
    const a = computeOrgScore(findings, ['a', 'b']);
    const b = computeOrgScore([...findings].reverse(), ['b', 'a']);
    expect(a.score).toBe(b.score);
    expect(a.contributions).toEqual(b.contributions);
  });

  it('ignores resolved / accepted / false-positive findings', () => {
    const r = computeOrgScore(
      [
        f({ severity: 'CRITICAL', assetId: 'a', status: 'RESOLVED' }),
        f({ severity: 'CRITICAL', assetId: 'a', status: 'FALSE_POSITIVE' }),
        f({ severity: 'CRITICAL', assetId: 'a', status: 'ACCEPTED_RISK' }),
      ],
      ['a'],
    );
    expect(r.score).toBe(100);
    expect(r.counts.CRITICAL).toBe(0);
  });

  it('clamps a very unhealthy asset at 0 rather than going negative', () => {
    const many = Array.from({ length: 6 }, (_, i) =>
      f({ severity: 'CRITICAL', assetId: 'a', checkId: `WIN-XX${i}-001` }),
    );
    const r = computeOrgScore(many, ['a']);
    expect(r.score).toBe(0);
    expect(r.band).toBe('Critical');
  });

  it('explains the score via sorted contributions', () => {
    const r = computeOrgScore(
      [
        f({ severity: 'HIGH', assetId: 'a', checkId: 'WIN-FW-001' }),
        f({ severity: 'HIGH', assetId: 'b', checkId: 'WIN-FW-001' }),
        f({ severity: 'LOW', assetId: 'a', checkId: 'WIN-LOG-002', category: 'Logging & Monitoring' }),
      ],
      ['a', 'b'],
    );
    expect(r.contributions[0]?.checkId).toBe('WIN-FW-001');
    expect(r.contributions[0]?.affectedAssets).toBe(2);
    expect(r.contributions[0]?.pointsDeducted).toBe(40);
  });

  it('computes per-category scores independently', () => {
    const r = computeOrgScore(
      [f({ severity: 'HIGH', assetId: 'a', category: 'Network Security' })],
      ['a'],
    );
    const net = r.categories.find((c) => c.category === 'Network Security');
    const idn = r.categories.find((c) => c.category === 'Identity & Access');
    expect(net?.score).toBe(80);
    expect(idn?.score).toBe(100);
  });
});

describe('bandFor', () => {
  it('maps boundaries correctly', () => {
    expect(bandFor(100)).toBe('Excellent');
    expect(bandFor(90)).toBe('Excellent');
    expect(bandFor(89)).toBe('Good');
    expect(bandFor(75)).toBe('Good');
    expect(bandFor(60)).toBe('Moderate');
    expect(bandFor(40)).toBe('Weak');
    expect(bandFor(39)).toBe('Critical');
    expect(bandFor(0)).toBe('Critical');
  });
});

describe('prioritize', () => {
  const p = (
    over: Partial<PrioritizableFinding> & { checkId: string; severity: Severity; assetId: string },
  ): PrioritizableFinding => ({
    checkName: over.checkName ?? over.checkId,
    category: (over.category ?? 'Network Security') as Category,
    status: (over.status ?? 'OPEN') as FindingStatus,
    effortMinutes: over.effortMinutes ?? 15,
    ...over,
  });

  it('groups by checkId and counts affected assets', () => {
    const items = prioritize(
      [
        p({ checkId: 'WIN-FW-001', severity: 'HIGH', assetId: 'a' }),
        p({ checkId: 'WIN-FW-001', severity: 'HIGH', assetId: 'b' }),
        p({ checkId: 'WIN-FW-001', severity: 'HIGH', assetId: 'c' }),
      ],
      5,
    );
    expect(items).toHaveLength(1);
    expect(items[0]?.affectedAssets).toBe(3);
    expect(items[0]?.rank).toBe(1);
  });

  it('ranks a fast fleet-wide HIGH above a slow single-host HIGH', () => {
    const items = prioritize(
      [
        p({ checkId: 'FAST-FLEET', severity: 'HIGH', assetId: 'a', effortMinutes: 10 }),
        p({ checkId: 'FAST-FLEET', severity: 'HIGH', assetId: 'b', effortMinutes: 10 }),
        p({ checkId: 'FAST-FLEET', severity: 'HIGH', assetId: 'c', effortMinutes: 10 }),
        p({ checkId: 'SLOW-ONE', severity: 'HIGH', assetId: 'a', effortMinutes: 240 }),
      ],
      3,
    );
    expect(items[0]?.checkId).toBe('FAST-FLEET');
  });

  it('down-weights findings where every result was a scanner ERROR', () => {
    const items = prioritize(
      [
        p({ checkId: 'CONF-OK', severity: 'MEDIUM', assetId: 'a' }),
        p({ checkId: 'CONF-ERR', severity: 'MEDIUM', assetId: 'a', isError: true }),
      ],
      1,
    );
    const ok = items.find((i) => i.checkId === 'CONF-OK')!;
    const err = items.find((i) => i.checkId === 'CONF-ERR')!;
    expect(ok.priorityScore).toBeGreaterThan(err.priorityScore);
  });

  it('excludes inactive findings', () => {
    const items = prioritize(
      [p({ checkId: 'WIN-FW-001', severity: 'HIGH', assetId: 'a', status: 'RESOLVED' })],
      1,
    );
    expect(items).toHaveLength(0);
  });

  it('is stable / deterministic across input permutations', () => {
    const input = [
      p({ checkId: 'A', severity: 'HIGH', assetId: 'a' }),
      p({ checkId: 'B', severity: 'MEDIUM', assetId: 'a' }),
      p({ checkId: 'C', severity: 'HIGH', assetId: 'b', category: 'Patch Management' }),
    ];
    const r1 = prioritize(input, 3).map((i) => i.checkId);
    const r2 = prioritize([...input].reverse(), 3).map((i) => i.checkId);
    expect(r1).toEqual(r2);
  });
});
