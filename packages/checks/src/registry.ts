import type { Platform } from '@smb/shared';
import { windowsChecks } from './checks/windows.js';
import { linuxChecks } from './checks/linux.js';
import type { SecurityCheck, SecurityCheckMeta } from './types.js';

const ALL: SecurityCheck[] = [...windowsChecks, ...linuxChecks];

const CHECK_ID_RE = /^[A-Z]{3}-[A-Z0-9]{2,6}-\d{3}$/;

const byId = new Map<string, SecurityCheck>();
for (const check of ALL) {
  if (!CHECK_ID_RE.test(check.id)) {
    throw new Error(`Invalid check id "${check.id}" (must match ${CHECK_ID_RE})`);
  }
  if (byId.has(check.id)) {
    throw new Error(`Duplicate check id "${check.id}" in the registry`);
  }
  byId.set(check.id, check);
}

/** Every registered check (frozen). */
export const allChecks: readonly SecurityCheck[] = Object.freeze([...ALL]);

/** Look up a check by id, or undefined if unknown. */
export function getCheck(id: string): SecurityCheck | undefined {
  return byId.get(id);
}

/**
 * Authoritative metadata for a check id. This is what the server trusts when
 * ingesting a scan — never the values in the uploaded JSON.
 * Throws on an unknown id so ingestion fails loudly (THREAT_MODEL T4).
 */
export function getCheckMeta(id: string): SecurityCheckMeta {
  const check = byId.get(id);
  if (!check) throw new UnknownCheckError(id);
  const { evaluate: _evaluate, ...meta } = check;
  return meta;
}

/** True if the id is a registered check. */
export function isKnownCheckId(id: string): boolean {
  return byId.has(id);
}

/** Throw if the id is not registered. */
export function assertKnownCheckId(id: string): void {
  if (!byId.has(id)) throw new UnknownCheckError(id);
}

/** Checks for a platform (or all), stable-sorted by id. */
export function listChecks(platform?: Platform): SecurityCheck[] {
  return ALL.filter((c) => !platform || c.platform === platform).sort((a, b) =>
    a.id.localeCompare(b.id),
  );
}

export class UnknownCheckError extends Error {
  constructor(public readonly checkId: string) {
    super(`Unknown checkId: ${checkId}`);
    this.name = 'UnknownCheckError';
  }
}
