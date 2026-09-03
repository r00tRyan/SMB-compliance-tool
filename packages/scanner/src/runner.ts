import os from 'node:os';
import { listChecks, type CollectorOutput, type SecurityCheck } from '@smb/checks';
import {
  SCAN_SCHEMA_VERSION,
  SecurityScanResultSchema,
  type Platform,
  type SecurityScanResult,
} from '@smb/shared';
import { collectorsForPlatform, getCollector, type CollectorDefinition } from './collectors/catalog.js';

export const SCANNER_VERSION = '0.1.0';

export interface ScanOptions {
  /** defaults to the host platform */
  platform?: Platform;
  /** restrict to these check ids */
  only?: string[];
  /** override the collector set (tests inject fakes) */
  collectors?: CollectorDefinition[];
  hostname?: string;
  osVersion?: string;
  now?: () => Date;
}

export interface ScanRunResult {
  result: SecurityScanResult;
  /** per-check evidence + resolved status, for the readable CLI output */
  checks: { check: SecurityCheck; status: string; evidence: string }[];
  /** collectors that could not run */
  collectorErrors: { id: string; error: string }[];
}

function hostPlatform(): Platform {
  if (process.platform === 'win32') return 'windows';
  if (process.platform === 'linux') return 'linux';
  throw new Error(`Unsupported platform "${process.platform}". The scanner supports Windows and Linux.`);
}

export async function runScan(opts: ScanOptions = {}): Promise<ScanRunResult> {
  const platform = opts.platform ?? hostPlatform();
  const now = opts.now ?? (() => new Date());
  const startedAt = now().toISOString();

  const allForPlatform = listChecks(platform);
  const checks = opts.only?.length
    ? allForPlatform.filter((c) => opts.only!.includes(c.id))
    : allForPlatform;

  if (checks.length === 0) {
    throw new Error(
      opts.only?.length
        ? `No matching checks for platform "${platform}": ${opts.only.join(', ')}`
        : `No checks registered for platform "${platform}"`,
    );
  }

  // Resolve the collectors these checks need.
  const catalog = opts.collectors ?? collectorsForPlatform(platform);
  const catalogById = new Map(catalog.map((c) => [c.id, c]));
  const neededIds = new Set<string>();
  for (const c of checks) for (const id of c.collectors) neededIds.add(id);

  const collected: Record<string, CollectorOutput> = {};
  const collectorErrors: { id: string; error: string }[] = [];

  await Promise.all(
    [...neededIds].map(async (id) => {
      const def = catalogById.get(id) ?? getCollector(id);
      if (!def) {
        collected[id] = { ok: false, text: '', error: `no collector registered for "${id}"` };
        collectorErrors.push({ id, error: 'no collector registered' });
        return;
      }
      try {
        const out = await def.run();
        collected[id] = out;
        if (!out.ok) collectorErrors.push({ id, error: out.error ?? 'collector failed' });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'collector threw';
        collected[id] = { ok: false, text: '', error };
        collectorErrors.push({ id, error });
      }
    }),
  );

  const asset = {
    hostname: opts.hostname ?? os.hostname(),
    platform,
    osVersion: opts.osVersion ?? `${os.type()} ${os.release()}`,
  };

  const evaluated = checks.map((check) => {
    const outcome = check.evaluate({ asset, collected });
    return { check, status: outcome.status, evidence: outcome.evidence };
  });

  const completedAt = now().toISOString();
  const result: SecurityScanResult = {
    schemaVersion: SCAN_SCHEMA_VERSION,
    asset,
    scan: { startedAt, completedAt, scannerVersion: SCANNER_VERSION },
    findings: evaluated.map((e) => ({
      checkId: e.check.id,
      status: e.status as SecurityScanResult['findings'][number]['status'],
      evidence: e.evidence,
      observedAt: completedAt,
    })),
  };

  // Self-check: never emit a payload our own ingestion schema would reject.
  const parsed = SecurityScanResultSchema.safeParse(result);
  if (!parsed.success) {
    throw new Error(`Scanner produced an invalid result: ${parsed.error.message}`);
  }

  return { result: parsed.data, checks: evaluated, collectorErrors };
}
