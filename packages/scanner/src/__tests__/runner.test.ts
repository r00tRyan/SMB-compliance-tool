import { describe, expect, it } from 'vitest';
import { SecurityScanResultSchema } from '@smb/shared';
import { listChecks } from '@smb/checks';
import { formatReadable, runScan, type CollectorDefinition } from '../index.js';

/** Build a fake collector set that returns canned text for given ids. */
type FakeOutput = string | { ok?: boolean; text?: string; error?: string };

function fakeCollectors(
  platform: 'windows' | 'linux',
  outputs: Record<string, FakeOutput>,
): CollectorDefinition[] {
  const ids = new Set<string>();
  for (const c of listChecks(platform)) for (const id of c.collectors) ids.add(id);
  return [...ids].map((id) => ({
    id,
    platform,
    describe: `fake ${id}`,
    run: async () => {
      const o = outputs[id];
      if (o === undefined) return { ok: false, text: '', error: 'not provided' };
      if (typeof o === 'string') return { ok: true, text: o };
      return { ok: o.ok ?? true, text: o.text ?? '', error: o.error };
    },
  }));
}

describe('runScan', () => {
  it('produces a schema-valid result and one finding per check', async () => {
    const collectors = fakeCollectors('windows', {
      'win.firewall.profiles':
        'Domain Profile Settings:\nState ON\nPrivate Profile Settings:\nState ON\nPublic Profile Settings:\nState ON',
      'win.defender.status': JSON.stringify({ RealTimeProtectionEnabled: true, AntivirusSignatureAge: 1 }),
      'win.localuser.guest': JSON.stringify({ Name: 'Guest', Enabled: false }),
    });
    const run = await runScan({
      platform: 'windows',
      collectors,
      hostname: 'TEST-PC',
      osVersion: 'Windows 11 Test',
      now: () => new Date('2026-09-03T10:00:00.000Z'),
    });

    expect(SecurityScanResultSchema.safeParse(run.result).success).toBe(true);
    expect(run.result.findings.length).toBe(listChecks('windows').length);
    expect(run.result.asset.hostname).toBe('TEST-PC');
    // Firewall check should PASS given all-ON evidence.
    const fw = run.result.findings.find((f) => f.checkId === 'WIN-FW-001');
    expect(fw?.status).toBe('PASS');
  });

  it('marks checks ERROR when their collector could not run', async () => {
    const run = await runScan({
      platform: 'windows',
      collectors: fakeCollectors('windows', {}), // everything "not provided"
      now: () => new Date('2026-09-03T10:00:00.000Z'),
    });
    const fw = run.result.findings.find((f) => f.checkId === 'WIN-FW-001');
    expect(fw?.status).toBe('ERROR');
    expect(run.collectorErrors.length).toBeGreaterThan(0);
  });

  it('honours --only', async () => {
    const run = await runScan({
      platform: 'linux',
      only: ['LNX-SSH-001'],
      collectors: fakeCollectors('linux', { 'lnx.sshd.effective': 'permitrootlogin no' }),
      now: () => new Date('2026-09-03T10:00:00.000Z'),
    });
    expect(run.result.findings).toHaveLength(1);
    expect(run.result.findings[0]?.checkId).toBe('LNX-SSH-001');
    expect(run.result.findings[0]?.status).toBe('PASS');
  });

  it('throws on an unknown --only id', async () => {
    await expect(
      runScan({ platform: 'windows', only: ['NOPE-XX-001'], collectors: fakeCollectors('windows', {}) }),
    ).rejects.toThrow(/No matching checks/);
  });

  it('formatReadable shows a summary line and failing evidence', async () => {
    const run = await runScan({
      platform: 'linux',
      only: ['LNX-SSH-001'],
      collectors: fakeCollectors('linux', { 'lnx.sshd.effective': 'permitrootlogin yes' }),
      now: () => new Date('2026-09-03T10:00:00.000Z'),
    });
    const text = formatReadable(run);
    expect(text).toMatch(/\[FAIL\] LNX-SSH-001/);
    expect(text).toMatch(/Summary:/);
  });
});
