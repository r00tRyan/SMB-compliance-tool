import 'server-only';
import { getCheck } from '@smb/checks';
import { SCAN_SCHEMA_VERSION, type Platform, type SecurityScanResult } from '@smb/shared';

/**
 * Demo data. Clearly fictional, tagged DEMO end-to-end, and never mixed with
 * real scans (enforced in ingest.ts by the isDemo/source guard).
 */
export const DEMO_ORG_NAME = 'Acme Dental';

interface DemoAssetSpec {
  name: string;
  platform: Platform;
  osVersion: string;
  /** checkId -> raw status for the FIRST (baseline) demo scan */
  baseline: Record<string, 'PASS' | 'FAIL' | 'WARN' | 'ERROR'>;
}

export const DEMO_ASSETS: DemoAssetSpec[] = [
  {
    name: 'ACME-PC-01',
    platform: 'windows',
    osVersion: 'Windows 11 Pro 23H2',
    baseline: {
      'WIN-FW-001': 'FAIL',
      'WIN-EPP-001': 'PASS',
      'WIN-EPP-002': 'PASS',
      'WIN-AUTH-001': 'PASS',
      'WIN-AUTH-002': 'FAIL',
      'WIN-AUTH-003': 'WARN',
      'WIN-RDP-001': 'PASS',
      'WIN-CFG-001': 'PASS',
      'WIN-SMB-001': 'FAIL',
      'WIN-DATA-001': 'PASS',
      'WIN-PATCH-001': 'PASS',
      'WIN-PATCH-002': 'WARN',
    },
  },
  {
    name: 'ACME-PC-02',
    platform: 'windows',
    osVersion: 'Windows 11 Pro 23H2',
    baseline: {
      'WIN-FW-001': 'FAIL',
      'WIN-EPP-001': 'PASS',
      'WIN-AUTH-001': 'PASS',
      'WIN-AUTH-002': 'FAIL',
      'WIN-DATA-001': 'FAIL',
      'WIN-SMB-001': 'PASS',
      'WIN-CFG-001': 'PASS',
      'WIN-PATCH-002': 'WARN',
    },
  },
  {
    name: 'ACME-PC-03',
    platform: 'windows',
    osVersion: 'Windows 10 Pro 22H2',
    baseline: {
      'WIN-FW-001': 'FAIL',
      'WIN-EPP-001': 'PASS',
      'WIN-EPP-002': 'WARN',
      'WIN-AUTH-001': 'FAIL',
      'WIN-AUTH-002': 'FAIL',
      'WIN-DATA-001': 'PASS',
      'WIN-PATCH-002': 'FAIL',
    },
  },
  {
    name: 'ACME-SERVER',
    platform: 'windows',
    osVersion: 'Windows Server 2022',
    baseline: {
      'WIN-FW-001': 'PASS',
      'WIN-EPP-001': 'PASS',
      'WIN-AUTH-001': 'PASS',
      'WIN-AUTH-004': 'WARN',
      'WIN-RDP-001': 'WARN',
      'WIN-RDP-002': 'FAIL',
      'WIN-LOG-001': 'WARN',
      'WIN-SMB-001': 'PASS',
      'WIN-DATA-001': 'PASS',
      'WIN-PATCH-001': 'PASS',
    },
  },
  {
    name: 'ACME-LINUX-01',
    platform: 'linux',
    osVersion: 'Ubuntu 22.04.4 LTS',
    baseline: {
      'LNX-FW-001': 'FAIL',
      'LNX-SSH-001': 'FAIL',
      'LNX-SSH-002': 'FAIL',
      'LNX-AUTH-001': 'PASS',
      'LNX-AUTH-002': 'WARN',
      'LNX-AUTH-003': 'FAIL',
      'LNX-PATCH-001': 'PASS',
      'LNX-PATCH-002': 'WARN',
      'LNX-PATCH-003': 'FAIL',
      'LNX-LOG-001': 'FAIL',
      'LNX-CFG-001': 'PASS',
    },
  },
];

/** A short fictional evidence line per raw status, per check. */
function demoEvidence(checkId: string, raw: string): string {
  const name = getCheck(checkId)?.name ?? checkId;
  switch (raw) {
    case 'PASS':
      return `DEMO: ${name} — configured as expected`;
    case 'WARN':
      return `DEMO: ${name} — configured but below recommended baseline`;
    case 'ERROR':
      return `DEMO: ${name} — could not be assessed in this demo`;
    default:
      return `DEMO: ${name} — not configured / disabled`;
  }
}

export function demoAssetSpec(name: string): DemoAssetSpec | undefined {
  return DEMO_ASSETS.find((a) => a.name === name);
}

/**
 * Build a demo scan result.
 * `fixCheckIds` flips those checks to PASS — used by the re-scan/verify flow so
 * a user can "remediate" a finding and see it resolve.
 */
export function buildDemoScan(
  spec: DemoAssetSpec,
  opts: { now?: Date; fixCheckIds?: string[] } = {},
): SecurityScanResult {
  const now = opts.now ?? new Date();
  const fixed = new Set(opts.fixCheckIds ?? []);
  const started = new Date(now.getTime() - 4000);

  return {
    schemaVersion: SCAN_SCHEMA_VERSION,
    asset: { hostname: spec.name, platform: spec.platform, osVersion: spec.osVersion },
    scan: {
      startedAt: started.toISOString(),
      completedAt: now.toISOString(),
      scannerVersion: '0.1.0-demo',
    },
    findings: Object.entries(spec.baseline).map(([checkId, raw]) => {
      const status = fixed.has(checkId) ? 'PASS' : raw;
      return {
        checkId,
        status,
        evidence: demoEvidence(checkId, status),
        observedAt: now.toISOString(),
      };
    }),
  };
}
