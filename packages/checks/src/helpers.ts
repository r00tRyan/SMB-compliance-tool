import type { CheckContext, CheckOutcome, CollectorOutput } from './types.js';

export const pass = (evidence: string): CheckOutcome => ({ status: 'PASS', evidence });
export const fail = (evidence: string): CheckOutcome => ({ status: 'FAIL', evidence });
export const warn = (evidence: string): CheckOutcome => ({ status: 'WARN', evidence });
export const notApplicable = (evidence: string): CheckOutcome => ({
  status: 'NOT_APPLICABLE',
  evidence,
});

/**
 * When a required collector could not run, the honest result is ERROR, not a
 * silent PASS/FAIL. The server treats ERROR findings as "could not assess".
 */
export const collectorError = (c: CollectorOutput | undefined, label: string): CheckOutcome => ({
  status: 'ERROR',
  evidence: `Could not assess ${label}: ${c?.error ?? 'collector output missing'}`,
});

/** Get a collector output, or a synthetic "missing" one. */
export function pick(ctx: CheckContext, id: string): CollectorOutput {
  return ctx.collected[id] ?? { ok: false, text: '', error: `collector "${id}" not provided` };
}

/** All declared collectors present and ok? */
export function haveAll(ctx: CheckContext, ...ids: string[]): boolean {
  return ids.every((id) => ctx.collected[id]?.ok);
}

/** Parse `key : value` / `key = value` lines into a lowercased-key map. */
export function parseKv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9 _.\-]+?)\s*[:=]\s*(.+?)\s*$/);
    if (m && m[1] && m[2] !== undefined) out[m[1].trim().toLowerCase()] = m[2].trim();
  }
  return out;
}

/** `net accounts` output -> normalized fields. */
export function parseNetAccounts(text: string): {
  minLength?: number;
  maxAgeDays?: number;
  lockoutThreshold?: number;
} {
  const kv = parseKv(text);
  const num = (v?: string): number | undefined => {
    if (v === undefined) return undefined;
    if (/never/i.test(v)) return Infinity;
    if (/none/i.test(v)) return 0;
    const n = parseInt(v.replace(/[^\d]/g, ''), 10);
    return Number.isNaN(n) ? undefined : n;
  };
  return {
    minLength: num(kv['minimum password length']),
    maxAgeDays: num(kv['maximum password age (days)']),
    lockoutThreshold: num(kv['lockout threshold']),
  };
}

/** True when text contains any of the (case-insensitive) needles. */
export function includesAny(text: string, ...needles: string[]): boolean {
  const t = text.toLowerCase();
  return needles.some((n) => t.includes(n.toLowerCase()));
}

/** First non-empty trimmed line. */
export function firstLine(text: string): string {
  return text.split(/\r?\n/).map((l) => l.trim()).find(Boolean) ?? '';
}
